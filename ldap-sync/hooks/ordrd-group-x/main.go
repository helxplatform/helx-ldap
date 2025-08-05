package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync"

	_ "main/docs"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// Global state
var (
	baseGid      int
	pidUidMap    = make(map[string]string)
	groupMembers = make(map[string][]string)
	mu           sync.Mutex
)

// HookRequest is the incoming payload
type HookRequest struct {
	DN      string                 `json:"dn" binding:"required"`
	Content map[string]interface{} `json:"content" binding:"required"`
}

// Entry is a transformed LDAP entry
type Entry struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

// SearchSpec defines a derived search
type SearchSpec struct {
	ID      string `json:"id"`
	Filter  string `json:"filter"`
	Refresh int    `json:"refresh"`
	BaseDN  string `json:"baseDN"`
	OneShot bool   `json:"oneshot"`
}

// HookResponse envelope
type HookResponse struct {
	Transformed  *Entry       `json:"transformed"`
	Derived      []SearchSpec `json:"derived"`
	Dependencies []string     `json:"dependencies"`
}

// @title ordrd-group-x Hook Service API
// @version 2.0.0
// @description Processes LDAP hook payloads and emits transformed, derived, and dependency data.
// @host localhost:5001
// @BasePath /
func main() {
	flag.IntVar(&baseGid, "baseGid", 0, "base GID for Type III output")
	flag.Parse()

	e := echo.New()
	e.Use(middleware.Logger(), middleware.Recover())

	e.POST("/hook", hookHandler)
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.Logger.Fatal(e.Start(":5001"))
}

// hookHandler processes incoming hook requests
// @Summary Process LDAP hook
// @Description Transform LDAP entries and generate derived searches + dependencies
// @Accept json
// @Produce json
// @Param payload body HookRequest true "Hook payload"
// @Success 200 {array} HookResponse
// @Router /hook [post]
func hookHandler(c echo.Context) error {
	var req HookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	responses := processHook(req)
	return c.JSON(http.StatusOK, responses)
}

func processHook(req HookRequest) []HookResponse {
	mu.Lock()
	defer mu.Unlock()

	var out []HookResponse
	content := req.Content

	// Detect Type1: UNC Group
	if isType1(content) {
		// parse deployment & groupname from cn
		cnRaw, ok := content["cn"].(string)
		if !ok {
			return out // malformed payload – cn is not a string
		}
		parts := strings.Split(cnRaw, ":")
		if len(parts) < 2 { // need at least deployment + group
			return out // or log error and skip
		}

		// always take the last two elements so prefix length can vary
		depl, grp := parts[len(parts)-2], parts[len(parts)-1]
		// collect pids
		rawMembers := content["member"].([]interface{})
		var pids []string
		for _, m := range rawMembers {
			s := m.(string)
			sub := strings.Split(s, ",")[0]
			pid := strings.TrimPrefix(sub, "pid=")
			pids = append(pids, pid)
			if _, ok := pidUidMap[pid]; !ok {
				pidUidMap[pid] = "" // placeholder
			}
		}
		groupMembers[grp] = pids

		// Type I output
		filter := "(|"
		for _, pid := range pids {
			filter += fmt.Sprintf("(pid=%s)", pid)
		}
		filter += ")"
		out = append(out, HookResponse{
			Transformed: nil,
			Derived: []SearchSpec{{
				ID:      fmt.Sprintf("ordrd-%s-%s-members", depl, grp),
				Filter:  filter,
				Refresh: 10,
				BaseDN:  "ou=people,dc=unc,dc=edu",
				OneShot: false,
			}},
			Dependencies: []string{},
		})

		// Type II (if all uids known)
		if allMapped := allHaveUIDs(pids); allMapped {
			memberDNs := []string{}
			for _, pid := range pids {
				uid := pidUidMap[pid]
				memberDNs = append(memberDNs,
					fmt.Sprintf("uid=%s,ou=users,dc=example,dc=org", uid))
			}
			out = append(out, HookResponse{
				Transformed: &Entry{
					DN: fmt.Sprintf("cn=%s,ou=groups,dc=example,dc=org", grp),
					Content: map[string]interface{}{
						"cn":          grp,
						"member":      memberDNs,
						"objectClass": []string{"top", "groupOfNames"},
					},
				},
				Derived:      []SearchSpec{},
				Dependencies: memberDNs,
			})
		}
	}

	// Detect Type2: UNC User
	if isType2(content) {
		pid := content["pid"].(string)
		uid := content["uid"].(string)
		pidUidMap[pid] = uid

		// Type II for any groups now ready
		for grp, pids := range groupMembers {
			if allHaveUIDs(pids) {
				memberDNs := []string{}
				for _, pid := range pids {
					uid := pidUidMap[pid]
					memberDNs = append(memberDNs,
						fmt.Sprintf("uid=%s,ou=users,dc=example,dc=org", uid))
				}
				out = append(out, HookResponse{
					Transformed: &Entry{
						DN: fmt.Sprintf("cn=%s,ou=groups,dc=example,dc=org", grp),
						Content: map[string]interface{}{
							"cn":          grp,
							"member":      memberDNs,
							"objectClass": []string{"top", "groupOfNames"},
						},
					},
					Derived:      []SearchSpec{},
					Dependencies: memberDNs,
				})
			}
		}

		// Type III output
		uidNum := content["uidNumber"].(string)
		out = append(out, HookResponse{
			Transformed: &Entry{
				DN: fmt.Sprintf("uid=%s,ou=users,dc=example,dc=org", uid),
				Content: map[string]interface{}{
					"cn":            content["cn"],
					"displayName":   content["displayName"],
					"gidNumber":     fmt.Sprintf("%d", baseGid),
					"givenName":     content["givenName"],
					"homeDirectory": fmt.Sprintf("/home/%s", uid),
					"objectClass":   []string{"top", "inetOrgPerson", "posixAccount", "helxUser"},
					"ou":            "users",
					"sn":            content["sn"],
					"uid":           uid,
					"uidNumber":     uidNum,
				},
			},
			Derived: []SearchSpec{{
				ID:      fmt.Sprintf("%s-posixGroups", uidNum),
				Filter:  fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", uidNum),
				Refresh: 10,
				BaseDN:  "dc=unc,dc=edu",
				OneShot: false,
			}},
			Dependencies: []string{},
		})
	}

	// Detect Type3: Posix group
	if isType3(content) {
		cn := content["cn"].(string)
		out = append(out, HookResponse{
			Transformed: &Entry{
				DN: fmt.Sprintf("cn=%s,ou=groups,dc=example,dc=org", cn),
				Content: map[string]interface{}{
					"cn":          cn,
					"description": content["description"],
					"gidNumber":   content["gidNumber"],
					"memberuid":   content["memberuid"],
					"objectClass": []string{"posixGroup"},
				},
			},
			Derived:      []SearchSpec{},
			Dependencies: []string{},
		})
	}

	return out
}

func isType1(c map[string]interface{}) bool {
	ocs, ok := c["objectClass"].([]interface{})
	if !ok {
		return false
	}
	for _, v := range ocs {
		if v == "UNCGroup" {
			_, hasMember := c["member"]
			return hasMember
		}
	}
	return false
}

func isType2(c map[string]interface{}) bool {
	_, hasPid := c["pid"]
	_, hasUid := c["uid"]
	return hasPid && hasUid
}

func isType3(c map[string]interface{}) bool {
	ocs, ok := c["objectClass"].([]interface{})
	if !ok {
		return false
	}
	for _, v := range ocs {
		if v == "posixGroup" {
			return true
		}
	}
	return false
}

func allHaveUIDs(pids []string) bool {
	for _, pid := range pids {
		if pidUidMap[pid] == "" {
			return false
		}
	}
	return true
}
