package main

import (
	"flag"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// @title           Hook Service
// @version         2.0.0
// @description     LDAP synchronization hook for ordrd-group-x
// @host            localhost:5001
// @BasePath        /

var (
	pidUidMap = make(map[string]string)
	baseGid   string
)

func init() {
	flag.StringVar(&baseGid, "baseGid", "1000", "base gid for new users")
}

func main() {
	flag.Parse()
	e := echo.New()
	e.Use(middleware.Logger())
	e.POST("/hook", hookHandler)
	log.Fatal(e.Start(":5001"))
}

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

// DerivedSearch represents a derived search definition.
// swagger:model
type DerivedSearch struct {
	ID      string `json:"id"`
	Filter  string `json:"filter"`
	Refresh int    `json:"refresh"`
	BaseDN  string `json:"baseDN"`
	Oneshot bool   `json:"oneshot"`
}

// TransformedEntry represents the transformed entry.
// swagger:model
type TransformedEntry struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

// HookResponse is the JSON response.
// swagger:model
type HookResponse struct {
	Transformed  *TransformedEntry `json:"transformed"`
	Derived      []DerivedSearch   `json:"derived"`
	Dependencies []string          `json:"dependencies"`
}

// hookHandler handles the /hook endpoint.
// @Summary      Process LDAP hook
// @Description  Transforms LDAP entries and derives searches
// @Accept       json
// @Produce      json
// @Param        body body HookRequest true "Hook request"
// @Success      200 {object} HookResponse
// @Router       /hook [post]
func hookHandler(c echo.Context) error {
	var req HookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if !validateDN(req.DN) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid DN"})
	}

	resp := processHook(req)
	for _, ds := range resp.Derived {
		if !validateFilter(ds.Filter) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid filter: " + ds.Filter})
		}
	}
	return c.JSON(http.StatusOK, resp)
}

func processHook(req HookRequest) HookResponse {
	// Example1: ORDRD Group
	if strings.HasPrefix(req.DN, "cn=unc:app:renci:ordrd:") {
		return processExample1(req)
	}
	// Example2: UNC User
	if strings.HasPrefix(req.DN, "pid=") {
		return processExample2(req)
	}
	// Example3: Posix Group
	if ocs, ok := req.Content["objectClass"].([]interface{}); ok {
		for _, oc := range ocs {
			if s, ok := oc.(string); ok && s == "posixGroup" {
				return processExample3(req)
			}
		}
	}
	// Unrecognized
	log.Printf("Unrecognized entry type for DN: %s", req.DN)
	return HookResponse{Transformed: nil, Derived: nil, Dependencies: nil}
}

func processExample1(req HookRequest) HookResponse {
	re := regexp.MustCompile(`^cn=unc:app:renci:ordrd:([^:]+):([^,]+)`)
	parts := re.FindStringSubmatch(req.DN)
	if len(parts) != 3 {
		return HookResponse{Transformed: nil, Derived: nil, Dependencies: nil}
	}
	deployment, groupname := parts[1], parts[2]
	members, ok := toStringSlice(req.Content["member"])
	if !ok {
		return HookResponse{Transformed: nil, Derived: nil, Dependencies: nil}
	}
	missing := []string{}
	for _, m := range members {
		pid := extractPID(m)
		if _, exists := pidUidMap[pid]; !exists {
			missing = append(missing, pid)
		}
	}
	// Case1: spawn a search
	if len(missing) > 0 {
		return HookResponse{
			Transformed: nil,
			Derived: []DerivedSearch{{
				ID:      "ordrd-" + deployment + "-" + groupname + "-members",
				Filter:  buildOrFilter("pid", missing),
				Refresh: 10,
				BaseDN:  "ou=people,dc=unc,dc=edu",
				Oneshot: false,
			}},
			Dependencies: nil,
		}
	}
	// Case2: all pids found
	newMembers, deps := []string{}, []string{}
	for _, m := range members {
		pid := extractPID(m)
		uid := pidUidMap[pid]
		dn := "uid=" + uid + ",ou=users,dc=example,dc=org"
		newMembers = append(newMembers, dn)
		deps = append(deps, dn)
	}
	trans := &TransformedEntry{
		DN: "cn=" + groupname + ",ou=groups,dc=example,dc=org",
		Content: map[string]interface{}{
			"cn":          groupname,
			"member":      newMembers,
			"objectClass": []string{"top", "groupOfNames"},
		},
	}
	return HookResponse{Transformed: trans, Derived: nil, Dependencies: deps}
}

func processExample2(req HookRequest) HookResponse {
	pid, _ := req.Content["pid"].(string)
	uid, _ := req.Content["uid"].(string)
	pidUidMap[pid] = uid

	trans := &TransformedEntry{
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
	uidNum, _ := req.Content["uidNumber"].(string)
	return HookResponse{
		Transformed: trans,
		Derived: []DerivedSearch{{
			ID:      uidNum + "-posixGroups",
			Filter:  "(&(objectClass=posixGroup)(memberUid=" + uidNum + "))",
			Refresh: 10,
			BaseDN:  "dc=unc,dc=edu",
			Oneshot: false,
		}},
		Dependencies: nil,
	}
}

func processExample3(req HookRequest) HookResponse {
	cn, _ := req.Content["cn"].(string)
	trans := &TransformedEntry{
		DN: "cn=" + cn + ",ou=groups,dc=example,dc=org",
		Content: map[string]interface{}{
			"cn":          cn,
			"description": req.Content["description"],
			"gidNumber":   req.Content["gidNumber"],
			"memberuid":   req.Content["memberuid"],
			"objectClass": []string{"posixGroup"},
		},
	}
	return HookResponse{Transformed: trans, Derived: nil, Dependencies: nil}
}

func toStringSlice(v interface{}) ([]string, bool) {
	raw, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, len(raw))
	for i, e := range raw {
		out[i], _ = e.(string)
	}
	return out, true
}

func extractPID(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	return strings.TrimPrefix(parts[0], "pid=")
}

func buildOrFilter(key string, vals []string) string {
	var sb strings.Builder
	sb.WriteString("(|")
	for _, v := range vals {
		sb.WriteString("(" + key + "=" + v + ")")
	}
	sb.WriteString(")")
	return sb.String()
}

// validateFilter ensures parentheses are balanced.
func validateFilter(f string) bool {
	open := 0
	for _, c := range f {
		if c == '(' {
			open++
		} else if c == ')' {
			open--
			if open < 0 {
				return false
			}
		}
	}
	return open == 0
}

// validateDN performs a basic sanity check on the DN.
func validateDN(dn string) bool {
	return strings.Contains(dn, "=")
}
