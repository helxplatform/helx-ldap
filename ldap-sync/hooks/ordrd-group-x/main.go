// main.go
package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// @title ordrd-group-x API
// @version 2.0.0
// @description Hook service for LDAP synchronization
// @host localhost:5001
// @BasePath /

var (
	baseGid     string
	pidUidMap   map[string]string
	groupPidMap map[string]GroupRecord
)

// Payload is the incoming hook payload.
type Payload struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

// Transformed is the object to write to destination LDAP.
type Transformed struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

// SearchSpec defines a derived search.
type SearchSpec struct {
	ID      string `json:"id"`
	Filter  string `json:"filter"`
	Refresh int    `json:"refresh"`
	BaseDN  string `json:"baseDN"`
	Oneshot bool   `json:"oneshot"`
}

// HookResponse is what we return to the caller.
type HookResponse struct {
	Transformed  *Transformed `json:"transformed"`
	Derived      []SearchSpec `json:"derived"`
	Dependencies []string     `json:"dependencies"`
}

// GroupRecord holds state for deferred group creation.
type GroupRecord struct {
	Deployment string
	GroupName  string
	PIDs       []string
}

// @Summary LDAP Hook
// @Description Processes LDAP hook payload and transforms or derives actions
// @Accept json
// @Produce json
// @Param payload body Payload true "Hook payload"
// @Success 200 {object} HookResponse
// @Router /hook [post]
func hookHandler(c echo.Context) error {
	var p Payload
	if err := c.Bind(&p); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid payload"})
	}
	resp := processPayload(p)
	return c.JSON(http.StatusOK, resp)
}

func main() {
	var port int
	flag.StringVar(&baseGid, "baseGid", "", "Base GID to assign in user transforms")
	flag.IntVar(&port, "port", 5001, "Port to listen on")
	flag.Parse()

	pidUidMap = make(map[string]string)
	groupPidMap = make(map[string]GroupRecord)

	e := echo.New()
	e.POST("/hook", hookHandler)
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
}

func processPayload(p Payload) HookResponse {
	switch {
	case isType1(p):
		return handleType1(p)
	case isType2(p):
		return handleType2(p)
	case isType3(p):
		return handleType3(p)
	default:
		// Unrecognized
		return HookResponse{Transformed: nil, Derived: nil, Dependencies: nil}
	}
}

func isType1(p Payload) bool {
	cls, ok := p.Content["objectClass"].([]interface{})
	if !ok {
		return false
	}
	foundGroup, foundUNC := false, false
	for _, v := range cls {
		if s, ok := v.(string); ok {
			if s == "groupOfNames" {
				foundGroup = true
			}
			if s == "UNCGroup" {
				foundUNC = true
			}
		}
	}
	return foundGroup && foundUNC
}

func handleType1(p Payload) HookResponse {
	cnRaw, _ := p.Content["cn"].(string)
	const prefix = "unc:app:renci:ordrd:"
	if !strings.HasPrefix(cnRaw, prefix) {
		return HookResponse{Transformed: nil, Derived: nil, Dependencies: nil}
	}
	rest := strings.TrimPrefix(cnRaw, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return HookResponse{Transformed: nil, Derived: nil, Dependencies: nil}
	}
	deployment, groupname := parts[0], parts[1]

	var pids []string
	if members, ok := p.Content["member"].([]interface{}); ok {
		for _, m := range members {
			if ms, ok := m.(string); ok && strings.HasPrefix(ms, "pid=") {
				if comma := strings.Index(ms, ","); comma > 0 {
					pids = append(pids, ms[len("pid="):comma])
				}
			}
		}
	}

	// keep for Type II
	key := fmt.Sprintf("%s:%s", deployment, groupname)
	groupPidMap[key] = GroupRecord{Deployment: deployment, GroupName: groupname, PIDs: pids}

	// build derived search
	filter := "(|"
	for _, pid := range pids {
		filter += fmt.Sprintf("(pid=%s)", pid)
	}
	filter += ")"

	spec := SearchSpec{
		ID:      fmt.Sprintf("ordrd-%s-%s-members", deployment, groupname),
		Filter:  filter,
		Refresh: 10,
		BaseDN:  "ou=people,dc=unc,dc=edu",
		Oneshot: false,
	}
	return HookResponse{Transformed: nil, Derived: []SearchSpec{spec}, Dependencies: nil}
}

func isType2(p Payload) bool {
	if _, ok := p.Content["pid"]; !ok {
		return false
	}
	if cls, ok := p.Content["objectClass"].([]interface{}); ok {
		for _, v := range cls {
			if s, ok := v.(string); ok && s == "posixAccount" {
				return true
			}
		}
	}
	return false
}

func handleType2(p Payload) HookResponse {
	pid, _ := p.Content["pid"].(string)
	uid, _ := p.Content["uid"].(string)
	pidUidMap[pid] = uid

	// build user transform
	newDN := fmt.Sprintf("uid=%s,ou=users,dc=example,dc=org", uid)
	newContent := map[string]interface{}{
		"cn":            p.Content["cn"],
		"displayName":   p.Content["displayName"],
		"gidNumber":     baseGid,
		"givenName":     p.Content["givenName"],
		"homeDirectory": fmt.Sprintf("/home/%s", uid),
		"objectClass":   []string{"top", "inetOrgPerson", "posixAccount", "helxUser"},
		"ou":            "users",
		"sn":            p.Content["sn"],
		"uid":           uid,
		"uidNumber":     p.Content["uidNumber"],
	}
	uidNum := fmt.Sprintf("%v", p.Content["uidNumber"])
	spec := SearchSpec{
		ID:      fmt.Sprintf("%s-posixGroups", uidNum),
		Filter:  fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", uidNum),
		Refresh: 10,
		BaseDN:  "dc=unc,dc=edu",
		Oneshot: false,
	}
	// check for any ready groups
	for k, gr := range groupPidMap {
		ready := true
		for _, pidVal := range gr.PIDs {
			if mapped, ok := pidUidMap[pidVal]; !ok || mapped == "" {
				ready = false
				break
			}
		}
		if ready {
			// emit Type II
			groupDN := fmt.Sprintf("cn=%s,ou=groups,dc=example,dc=org", gr.GroupName)
			members := make([]string, 0, len(gr.PIDs))
			deps := make([]string, 0, len(gr.PIDs))
			for _, pidVal := range gr.PIDs {
				u := pidUidMap[pidVal]
				dn := fmt.Sprintf("uid=%s,ou=users,dc=example,dc=org", u)
				members = append(members, dn)
				deps = append(deps, dn)
			}
			delete(groupPidMap, k)
			return HookResponse{
				Transformed: &Transformed{DN: groupDN, Content: map[string]interface{}{
					"cn":          gr.GroupName,
					"member":      members,
					"objectClass": []string{"top", "groupOfNames"},
				}},
				Derived:      nil,
				Dependencies: deps,
			}
		}
	}
	// else return user transform
	return HookResponse{
		Transformed:  &Transformed{DN: newDN, Content: newContent},
		Derived:      []SearchSpec{spec},
		Dependencies: nil,
	}
}

func isType3(p Payload) bool {
	if cls, ok := p.Content["objectClass"].([]interface{}); ok {
		for _, v := range cls {
			if s, ok := v.(string); ok && s == "posixGroup" {
				return true
			}
		}
	}
	return false
}

func handleType3(p Payload) HookResponse {
	cn, _ := p.Content["cn"].(string)
	newDN := fmt.Sprintf("cn=%s,ou=groups,dc=example,dc=org", cn)
	newContent := map[string]interface{}{
		"cn":          cn,
		"description": p.Content["description"],
		"gidNumber":   p.Content["gidNumber"],
		"memberuid":   p.Content["memberuid"],
		"objectClass": []string{"posixGroup"},
	}
	return HookResponse{
		Transformed:  &Transformed{DN: newDN, Content: newContent},
		Derived:      nil,
		Dependencies: nil,
	}
}
