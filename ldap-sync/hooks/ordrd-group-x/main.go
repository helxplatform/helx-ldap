package main

import (
	"flag"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// @title           Hook Service
// @version         2.0.0
// @description     LDAP synchronization hook for ordrd-group-x
// @host            localhost:5001
// @BasePath        /

// HookRequest is the incoming payload.
// swagger:model
type HookRequest struct {
	// Distinguished Name of the LDAP entry
	// required: true
	DN string `json:"dn"`
	// Attributes of the entry
	// required: true
	Content map[string]interface{} `json:"content"`
}

// SearchSpec defines an LDAP search to derive.
// swagger:model
type SearchSpec struct {
	ID      string `json:"id"`
	Filter  string `json:"filter"`
	Refresh int    `json:"refresh"`
	BaseDN  string `json:"baseDN"`
	Oneshot bool   `json:"oneshot"`
}

// TransformedEntry is the object to write.
// swagger:model
type TransformedEntry struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

// HookResponse is the outgoing payload.
// swagger:model
type HookResponse struct {
	Transformed  *TransformedEntry `json:"transformed"`
	Derived      []SearchSpec      `json:"derived"`
	Dependencies []string          `json:"dependencies"`
}

// ErrorResponse for bad requests.
type ErrorResponse struct {
	Message string `json:"message"`
}

var (
	pidUidMap = make(map[string]string)
	baseGid   string
)

func init() {
	flag.StringVar(&baseGid, "baseGid", "1000", "Base GID for all users")
}

func main() {
	flag.Parse()
	e := echo.New()
	e.Use(middleware.Logger())
	e.POST("/hook", hookHandler)
	e.Logger.Fatal(e.Start(":5001"))
}

// hookHandler processes /hook requests.
// @Summary      Process LDAP hook
// @Description  Transform LDAP entries, derive searches, declare dependencies
// @Accept       json
// @Produce      json
// @Param        hook  body      HookRequest  true  "Hook payload"
// @Success      200   {object}  HookResponse
// @Failure      400   {object}  ErrorResponse
// @Router       /hook [post]
func hookHandler(c echo.Context) error {
	var req HookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Message: "invalid JSON"})
	}
	if req.DN == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Message: "dn is required"})
	}

	resp := processHook(req)
	return c.JSON(http.StatusOK, resp)
}

// processHook contains sample logic; replace with your own handlers.
func processHook(req HookRequest) HookResponse {
	var (
		transformed  *TransformedEntry
		derived      []SearchSpec
		dependencies []string
	)

	oc, _ := req.Content["objectClass"].([]interface{})

	// Example2: UNC User (pid=...)
	if strings.HasPrefix(req.DN, "pid=") {
		uid := req.Content["uid"].(string)
		pid := req.Content["pid"].(string)
		// populate pidUidMap
		pidUidMap[pid] = uid

		transformed = &TransformedEntry{
			DN: "uid=" + uid + ",ou=users,dc=example,dc=org",
			Content: map[string]interface{}{
				"cn":            req.Content["cn"],
				"displayName":   req.Content["displayName"],
				"gidNumber":     baseGid,
				"givenName":     req.Content["givenName"],
				"homeDirectory": "/home/" + uid,
				"objectClass":   []string{"top", "inetOrgPerson", "posixAccount", "helxUser"},
				"ou":            "users",
				"sn":            req.Content["sn"],
				"uid":           uid,
				"uidNumber":     req.Content["uidNumber"],
			},
		}
		derived = []SearchSpec{{
			ID:      req.Content["uidNumber"].(string) + "-posixGroups",
			Filter:  "(&(objectClass=posixGroup)(memberUid=" + req.Content["uidNumber"].(string) + "))",
			Refresh: 10,
			BaseDN:  "dc=unc,dc=edu",
			Oneshot: false,
		}}
		return HookResponse{transformed, derived, nil}
	}

	// Example3: posixGroup
	for _, v := range oc {
		if v == "posixGroup" {
			transformed = &TransformedEntry{
				DN: "cn=" + req.Content["cn"].(string) + ",ou=groups,dc=example,dc=org",
				Content: map[string]interface{}{
					"cn":          req.Content["cn"],
					"description": req.Content["description"],
					"gidNumber":   req.Content["gidNumber"],
					"memberuid":   req.Content["memberuid"],
					"objectClass": []string{"posixGroup"},
				},
			}
			return HookResponse{transformed, nil, nil}
		}
	}

	// Example1: ordrd group
	if strings.Contains(req.DN, "ou=Groups") {
		memberIface, _ := req.Content["member"].([]interface{})
		var pids []string
		for _, m := range memberIface {
			parts := strings.Split(m.(string), ",")[0] // pid=...
			pids = append(pids, parts)
		}
		// if any missing, derive lookup
		missing := false
		for _, pid := range pids {
			if _, ok := pidUidMap[strings.TrimPrefix(pid, "pid=")]; !ok {
				missing = true
				break
			}
		}
		if missing {
			derived = []SearchSpec{{
				ID:      "ordrd-members",
				Filter:  "(|" + strings.Join(pids, ")(") + ")",
				Refresh: 10,
				BaseDN:  "ou=people,dc=unc,dc=edu",
				Oneshot: false,
			}}
			return HookResponse{nil, derived, nil}
		}
		// all present: transform
		var members []string
		for _, pid := range pids {
			uid := pidUidMap[strings.TrimPrefix(pid, "pid=")]
			uidDN := "uid=" + uid + ",ou=users,dc=example,dc=org"
			members = append(members, uidDN)
			dependencies = append(dependencies, uidDN)
		}
		transformed = &TransformedEntry{
			DN: "cn={{ groupname }},ou=groups,dc=example,dc=org",
			Content: map[string]interface{}{
				"cn":          "{{ groupname }}",
				"member":      members,
				"objectClass": []string{"top", "groupOfNames"},
			},
		}
		return HookResponse{transformed, nil, dependencies}
	}

	// Unrecognized: no-op
	return HookResponse{nil, nil, nil}
}
