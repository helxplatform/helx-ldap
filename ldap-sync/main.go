package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "main/docs" // Replace with your actual module path.

	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
	"gopkg.in/yaml.v2"
)

// LDAPConfig holds connection details for one LDAP server.
type LDAPConfig struct {
	URL          string `yaml:"url"`
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	BaseDN       string `yaml:"base_dn"`
}

// Config holds the configuration for both source and target LDAP servers.
type Config struct {
	Source LDAPConfig `yaml:"source"`
	Target LDAPConfig `yaml:"target"`
	Hooks  []string   `yaml:"hooks"`
}

// SearchSpec represents a running search instance.
type SearchSpec struct {
	Filter  string
	Refresh int
	Stop    chan struct{}
	BaseDN  string // The base DN to use for this search.
	Oneshot bool   // one-shot -- don't involve the hook
}

// LogLevelRequest represents the payload for updating the log level.
type LogLevelRequest struct {
	Level string `json:"level"`
}

// SearchInfo represents the JSON structure for a search.
type SearchInfo struct {
	ID      string `json:"id"`
	Filter  string `json:"filter"`
	Refresh int    `json:"refresh"`
	BaseDN  string
	Oneshot bool
}

// DerivedSearchSpec describes a search as provided via a hook response.
type DerivedSearchSpec struct {
	ID      string `json:"id"`
	Filter  string `json:"filter"`
	Refresh int    `json:"refresh"`
	BaseDN  string `json:"baseDN"`
	Oneshot bool   `json:"oneshot"`
}

// LDAPResult holds an LDAP entry in a structured way.
type LDAPResult struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

// Define two result types.
type LDAPResultSimple struct {
	DN string `json:"dn"`
}

/*
type ResultEntryFull struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}

type TransformedEntry struct {
	DN      string                 `json:"dn"`
	Content map[string]interface{} `json:"content"`
}
*/

// HookResponse represents the hook response JSON.
type HookResponse struct {
	Transformed *LDAPResult         `json:"transformed"`
	Derived     []DerivedSearchSpec `json:"derived"`
	// Only once all of these DNs exist in the target LDAP
	// should we store Transformed.
	Dependencies []string `json:"dependencies"`
}

// SearchTask holds everything we need to schedule one LDAP search.
type SearchTask struct {
	ID       string
	Filter   string
	BaseDN   string
	Interval time.Duration
	NextRun  time.Time
	OneShot  bool
}

var config Config
var logger *slog.Logger
var currentLogLevel string

// var searches = make(map[string]*SearchSpec)
var searchResults = make(map[string]map[string]LDAPResult)

// map of searchID → *SearchTask
var searchTasks = make(map[string]*SearchTask)

// Mutex protecting access to searchTasks and results
var searchTasksMutex = &sync.RWMutex{}
var searchResultsMutex = &sync.RWMutex{}

// Channels to wake the scheduler when searchTasks changes and communicate
// interesting LDAP results
var schedulerWakeUp = make(chan struct{})
var hookEventsCh = make(chan LDAPResult, 100)
var derivedSearchCh = make(chan DerivedSearchSpec, 100)

// initLogger initializes the logger using log/slog.
// It checks the --loglevel flag first, then the LOG_LEVEL env variable,
// and defaults to "info" if neither is set.
func initLogger(loglevel string) {
	lvlStr := os.Getenv("LOG_LEVEL")
	if loglevel != "" {
		lvlStr = loglevel
	}
	if lvlStr == "" {
		lvlStr = "info"
	}
	var lvl slog.Level = slog.LevelInfo
	switch strings.ToLower(lvlStr) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	case "info":
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     lvl,
		AddSource: true,
	})
	logger = slog.New(h)
	logger.Info("Logger initialized", "level", lvlStr)
}

// setLogLevel updates the global logger to the new level.
func setLogLevel(newLevel string) {
	var lvl slog.Level = slog.LevelInfo
	switch strings.ToLower(newLevel) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	case "info":
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     lvl,
		AddSource: true,
	})
	logger = slog.New(h)
	logger.Info("Log level updated", "newLevel", newLevel)
}

// loadConfig reads the YAML config file
func loadConfig(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

// connectAndBindLDAP connects to the LDAP server using the source configuration and binds using the credentials.
// Returns an established connection or an error.
func connectAndBindLDAP() (*ldap.Conn, error) {
	l, err := ldap.DialURL(config.Source.URL)
	if err != nil {
		return nil, err
	}
	if err = l.Bind(config.Source.BindDN, config.Source.BindPassword); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// performLDAPSearch performs an LDAP search using the provided connection, baseDN, and filter.
func performLDAPSearch(l *ldap.Conn, baseDN, filter string) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"*"},
		nil,
	)
	return l.Search(searchRequest)
}

func storeDestinationLDAP(entry *LDAPResult) error {
	// Connect to destination LDAP.
	l, err := ldap.DialURL(config.Target.URL)
	if err != nil {
		return err
	}
	defer l.Close()

	// Bind with destination credentials.
	if err = l.Bind(config.Target.BindDN, config.Target.BindPassword); err != nil {
		return err
	}

	// Check if the entry exists.
	searchRequest := ldap.NewSearchRequest(
		entry.DN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		// Check if the error is LDAP error code 32 ("No Such Object")
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			// Treat it as if no entry was found.
			sr = &ldap.SearchResult{Entries: []*ldap.Entry{}}
		} else {
			return err
		}
	}

	// Prepare attributes conversion: each attribute becomes a slice of strings.
	attributes := make(map[string][]string)
	for attr, value := range entry.Content {
		switch v := value.(type) {
		case []interface{}:
			var vals []string
			for _, x := range v {
				vals = append(vals, fmt.Sprintf("%v", x))
			}
			attributes[attr] = vals
		default:
			attributes[attr] = []string{fmt.Sprintf("%v", v)}
		}
	}

	// If the entry doesn't exist, add it.
	if len(sr.Entries) == 0 {
		addReq := ldap.NewAddRequest(entry.DN, nil)
		for attr, values := range attributes {
			addReq.Attribute(attr, values)
		}
		// Optionally, ensure an objectClass is set.
		if _, exists := attributes["objectClass"]; !exists {
			addReq.Attribute("objectClass", []string{"top", "inetOrgPerson"})
		}
		if err = l.Add(addReq); err != nil {
			return err
		}
		logger.Info("Added entry to destination LDAP", "DN", entry.DN)
	} else {
		// If the entry exists, update it.
		modReq := ldap.NewModifyRequest(entry.DN, nil)
		for attr, values := range attributes {
			modReq.Replace(attr, values)
		}
		if err = l.Modify(modReq); err != nil {
			return err
		}
		logger.Info("Modified entry in destination LDAP", "DN", entry.DN)
	}
	return nil
}

/*
// ldapSearchAndSync performs the LDAP search on the source server and synchronizes the results.
func ldapSearchAndSync(id, filter, baseDN string, refresh int, oneshot bool, stopChan chan struct{}) {
	for {
		select {
		case <-stopChan:
			logger.Info("Search cancelled", "SearchId", id)
			return
		default:
		}

		logger.Debug("Performing LDAP search with filter", "Filter", filter, "SearchId", id, "BaseDN", baseDN)
		l, err := connectAndBindLDAP()
		if err != nil {
			logger.Error("Error connecting and binding to LDAP", "Err", err)
			select {
			case <-stopChan:
				return
			case <-time.After(time.Duration(refresh) * time.Second):
			}
			continue
		}

		sr, err := performLDAPSearch(l, baseDN, filter)
		if err != nil {
			logger.Error("Error performing search", "Err", err)
			l.Close()
			select {
			case <-stopChan:
				return
			case <-time.After(time.Duration(refresh) * time.Second):
			}
			continue
		}
		l.Close()

		for _, entry := range sr.Entries {
			processLDAPEntry(id, entry, oneshot)
		}

		// If one-shot mode is active, exit after one iteration.
		if oneshot {
			logger.Info("One-shot search completed", "SearchId", id)
			return
		}

		select {
		case <-stopChan:
			logger.Debug("Search cancelled", "SearchId", id)
			return
		case <-time.After(time.Duration(refresh) * time.Second):
		}
	}
}
*/

// destinationEntryExists returns true if the given DN is present
// in the destination server.
func destinationEntryExists(dn string) bool {
	l, err := ldap.DialURL(config.Target.URL)
	if err != nil {
		logger.Error("Dial target LDAP failed", "DN", dn, "Err", err)
		return false
	}
	defer l.Close()

	if err := l.Bind(config.Target.BindDN, config.Target.BindPassword); err != nil {
		logger.Error("Bind target LDAP failed", "DN", dn, "Err", err)
		return false
	}

	sr, err := l.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 1, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	))
	if err != nil {
		logger.Error("Search target LDAP failed", "DN", dn, "Err", err)
		return false
	}
	return len(sr.Entries) > 0
}

// allDepsExist returns true only if every DN in deps is present.
func allDepsExist(deps []string) bool {
	for _, dn := range deps {
		if !destinationEntryExists(dn) {
			return false
		}
	}
	return true
}

func processHookResponse(hookResp HookResponse) {
	logger.Debug("Processing Hook response",
		"Transformed", hookResp.Transformed,
		"Derived", hookResp.Derived,
		"Dependencies", hookResp.Dependencies,
	)

	// 1) Handle the transformed entry only once its dependencies are satisfied
	if hookResp.Transformed != nil {
		// If no dependencies, store immediately; otherwise wait
		if len(hookResp.Dependencies) == 0 || allDepsExist(hookResp.Dependencies) {
			if err := storeDestinationLDAP(hookResp.Transformed); err != nil {
				logger.Error("Error storing entry in destination LDAP",
					"DN", hookResp.Transformed.DN, "Err", err)
			}
		} else {
			logger.Info("Deferring store; unmet dependencies",
				"DN", hookResp.Transformed.DN,
				"WaitingFor", hookResp.Dependencies,
			)
			// Optionally: you could re-queue this HookResponse for retry,
			// or rely on the hook system to re-send once the derived entries exist.
		}
	} else {
		logger.Info("No transformed payload; skipping store")
	}

	// enqueue each derived spec for the central processor
	for _, ds := range hookResp.Derived {
		derivedSearchCh <- ds
	}
}

// sendHooks posts the LDAP result to each URL specified in config.Hooks.
func sendHooks(result LDAPResult) {
	payload, err := json.Marshal(result)
	if err != nil {
		logger.Error("Error marshalling hook payload for DN", "DN", result.DN, "Err", err)
		return
	}
	for _, url := range config.Hooks {
		// Launch each hook call concurrently.
		go func(hookURL string) {
			resp, err := http.Post(hookURL, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				logger.Error("Error posting to hook", "URL", hookURL, "Err", err)
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				logger.Error("Error reading hook response", "URL", hookURL, "Err", err)
				return
			}

			var hookResp HookResponse

			if err := json.Unmarshal(body, &hookResp); err != nil {
				logger.Error("Error unmarshalling hook response", "URL", hookURL, "Err", err)
				return
			}
			processHookResponse(hookResp)
		}(url)
	}
}

func processLDAPEntry(searchID string, entry *ldap.Entry, oneShot bool) {
	// build the map[string]interface{} as before
	dn := entry.DN
	attrMap := make(map[string]interface{}, len(entry.Attributes))
	for _, attr := range entry.Attributes {
		if len(attr.Values) == 1 {
			attrMap[attr.Name] = attr.Values[0]
		} else {
			attrMap[attr.Name] = attr.Values
		}
	}

	newResult := LDAPResult{DN: dn, Content: attrMap}

	// update the shared searchResults under lock
	searchResultsMutex.Lock()
	defer searchResultsMutex.Unlock()
	resultsMap, ok := searchResults[searchID]
	if !ok {
		resultsMap = make(map[string]LDAPResult)
		searchResults[searchID] = resultsMap
	}

	existing, exists := resultsMap[dn]
	if !exists {
		// new entry
		resultsMap[dn] = newResult
		logger.Info("New item retrieved", "DN", dn, "SearchId", searchID)
		if !oneShot {
			hookEventsCh <- newResult
		}
	} else if !reflect.DeepEqual(existing.Content, attrMap) {
		// updated entry
		resultsMap[dn] = newResult
		logger.Info("Updated item", "DN", dn, "SearchId", searchID)
		if !oneShot {
			hookEventsCh <- newResult
		}
	} else {
		// unchanged
		logger.Debug("No change", "DN", dn, "SearchId", searchID)
	}
}

// runSearchScheduler drives all LDAP searches in a single goroutine.
func runSearchScheduler(tasks map[string]*SearchTask, tasksMu *sync.RWMutex, wakeUp <-chan struct{}) {
	for {
		// 1) Lock and dispatch any due tasks
		tasksMu.Lock()
		now := time.Now()

		logger.Info("scanning tasks")

		for id, t := range tasks {
			if !t.NextRun.After(now) {
				// Connect & bind using your helper
				conn, err := connectAndBindLDAP()
				if err != nil {
					logger.Error("LDAP connect/bind failed", "SearchID", id, "Err", err)
				} else {
					// Perform the search
					sr, err := performLDAPSearch(conn, t.BaseDN, t.Filter)
					conn.Close()
					if err != nil {
						logger.Error("LDAP search failed", "SearchID", id, "Err", err)
					} else {
						for _, entry := range sr.Entries {
							processLDAPEntry(id, entry, t.OneShot)
						}
					}
				}

				// Remove one-shots, or schedule next run
				if t.OneShot {
					delete(tasks, id)
				} else {
					t.NextRun = now.Add(t.Interval)
				}
			}
		}

		// 2) Figure out the next wake-up time
		var nextWake time.Time
		for _, t := range tasks {
			if nextWake.IsZero() || t.NextRun.Before(nextWake) {
				nextWake = t.NextRun
			}
		}
		tasksMu.Unlock()

		// 3) If nothing left, block until a new task appears
		if nextWake.IsZero() {
			<-wakeUp
			continue
		}

		// 4) Sleep until then (min granularity 1s), or wake early on update
		sleepDur := time.Until(nextWake)
		if sleepDur < time.Second {
			sleepDur = time.Second
		}
		select {
		case <-time.After(sleepDur):
		case <-wakeUp:
		}
	}
}

// upsertSearchTask inserts or updates a task atomically.
//
//	– requireNotExists: if true, error if task already exists (for POST semantics)
//	– requireExists:    if true, error if task does NOT exist (for PUT semantics)
func upsertSearchTask(id, filter, baseDN string, refreshSec int, oneShot bool, requireNotExists bool, requireExists bool) error {
	var nextRun time.Time

	searchTasksMutex.Lock()
	defer searchTasksMutex.Unlock()

	_, exists := searchTasks[id]
	if requireNotExists && exists {
		return fmt.Errorf("search %q already exists", id)
	}
	if requireExists && !exists {
		return fmt.Errorf("search %q does not exist", id)
	}

	// Insert or overwrite the task:
	searchTasks[id] = &SearchTask{ID: id, Filter: filter, BaseDN: baseDN, Interval: time.Duration(refreshSec) * time.Second, NextRun: nextRun, OneShot: oneShot}

	// Wake the scheduler so it can recalc immediately
	go func() { schedulerWakeUp <- struct{}{} }()
	return nil
}

// deleteSearchTask atomically removes a scheduled search.
func deleteSearchTask(id string) error {
	searchTasksMutex.Lock()
	defer searchTasksMutex.Unlock()

	if _, exists := searchTasks[id]; !exists {
		return fmt.Errorf("search %q not found", id)
	}

	delete(searchTasks, id)
	// Wake the scheduler so it notices the deletion immediately
	go func() { schedulerWakeUp <- struct{}{} }()
	return nil
}

// startBackgroundWorkers spins up:
//   - the hook‐processor loop
//   - the derived-search loop
//   - the central LDAP-search scheduler
func startBackgroundWorkers() {
	// 1) Hook-processor: consume new/changed LDAPResults → sendHooks
	go func() {
		for res := range hookEventsCh {
			sendHooks(res)
		}
	}()

	// 2) Derived-search processor: consume DerivedSearchSpecs → upsert tasks
	go func() {
		for ds := range derivedSearchCh {
			baseDN := ds.BaseDN
			if baseDN == "" {
				baseDN = config.Source.BaseDN
			}
			if err := upsertSearchTask(ds.ID, ds.Filter, baseDN, ds.Refresh, ds.Oneshot, false, false); err != nil {
				logger.Error("Failed to schedule derived search", "SearchId", ds.ID, "Err", err)
			} else {
				logger.Info("Derived search scheduled/updated", "SearchId", ds.ID)
			}
		}
	}()

	// 3) Central scheduler driving all LDAP searches
	go runSearchScheduler(searchTasks, searchTasksMutex, schedulerWakeUp)
}

// createSearchHandler godoc
// @Summary Create new search
// @Description Creates a new search with a unique id. Returns an error if the id already exists.
// @Tags search
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param id formData string true "Unique search id"
// @Param filter formData string true "LDAP search filter"
// @Param refresh formData int true "Refresh interval in seconds"
// @Param baseDN formData string false "Optional base DN for the search; defaults to global config if omitted"
// @Param oneShot formData bool false "If set to true, the search will run in one-shot mode (hook subsystem will not be engaged). Defaults to true."
// @Success 200 {string} string "Search created"
// @Failure 400 {string} string "Invalid parameters or search already exists"
// @Router /search [post]
func createSearchHandler(c echo.Context) error {
	id := c.FormValue("id")
	filter := strings.TrimSpace(c.FormValue("filter"))
	refreshStr := c.FormValue("refresh")
	baseDN := c.FormValue("baseDN")
	if baseDN == "" {
		baseDN = config.Source.BaseDN
	}
	if id == "" || filter == "" || refreshStr == "" {
		return c.String(http.StatusBadRequest, "Missing required parameters (id, filter, refresh)")
	}

	// Parse refresh interval
	refreshSec, err := strconv.Atoi(refreshStr)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid refresh parameter")
	}

	// Parse oneShot flag
	oneShot := true
	if os := c.FormValue("oneShot"); os != "" {
		if parsed, err := strconv.ParseBool(os); err != nil {
			return c.String(http.StatusBadRequest, "Invalid oneShot parameter")
		} else {
			oneShot = parsed
		}
	}

	// Atomically insert, rejecting if already present:
	if err := upsertSearchTask(id, filter, baseDN, refreshSec, oneShot, true, false); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.String(http.StatusOK, "Search created")
}

// getSearchHandler godoc
// @Summary Get search(s)
// @Description Retrieves a specific search by id if provided, or all searches if no id is specified.
// @Tags search
// @Accept json
// @Produce json
// @Param id query string false "Search ID"
// @Success 200 {object} SearchInfo "When id is provided" or {array} SearchInfo "When id is not provided"
// @Failure 404 {string} string "Search not found"
// @Router /search [get]
func getSearchHandler(c echo.Context) error {
	id := c.QueryParam("id")

	// Lock for reading the searchTasks map
	searchTasksMutex.RLock()
	defer searchTasksMutex.RUnlock()

	if id != "" {
		spec, exists := searchTasks[id]
		if !exists {
			return c.String(http.StatusNotFound, "Search with given id not found")
		}
		// Build response from the locked spec
		result := SearchInfo{
			ID:      spec.ID,
			Filter:  spec.Filter,
			Refresh: int(spec.Interval.Seconds()),
			BaseDN:  spec.BaseDN,
			Oneshot: spec.OneShot,
		}
		return c.JSON(http.StatusOK, result)
	}

	// No id provided; copy all into a slice
	results := make([]SearchInfo, 0, len(searchTasks))
	for _, spec := range searchTasks {
		results = append(results, SearchInfo{
			ID:      spec.ID,
			Filter:  spec.Filter,
			Refresh: int(spec.Interval.Seconds()),
			BaseDN:  spec.BaseDN,
			Oneshot: spec.OneShot,
		})
	}
	return c.JSON(http.StatusOK, results)
}

// updateSearchHandler godoc
// @Summary Update existing search
// @Description Updates an existing search (complete replacement) with new filter, refresh, and optionally baseDN. If baseDN is omitted, the global config's BaseDN is used.
// @Tags search
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param id path string true "Unique search id"
// @Param filter formData string true "LDAP search filter"
// @Param refresh formData int true "Refresh interval in seconds"
// @Param baseDN formData string false "Optional base DN for the search; defaults to global config if omitted"
// @Param oneShot formData bool false "If set to true, the search will run in one-shot mode (hook subsystem will not be engaged). Defaults to true."
// @Success 200 {string} string "Search updated"
// @Failure 400 {string} string "Invalid parameters or search does not exist"
// @Router /search/{id} [put]
func updateSearchHandler(c echo.Context) error {
	id := c.Param("id")
	filter := strings.TrimSpace(c.FormValue("filter"))
	refreshStr := c.FormValue("refresh")
	baseDN := c.FormValue("baseDN")
	if baseDN == "" {
		baseDN = config.Source.BaseDN
	}
	if id == "" || filter == "" || refreshStr == "" {
		return c.String(http.StatusBadRequest, "Missing required parameters (id, filter, refresh)")
	}
	refresh, err := strconv.Atoi(refreshStr)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid refresh parameter")
	}

	// Parse oneShot parameter; default to true if not provided.
	oneShotStr := c.FormValue("oneShot")
	oneshot := true
	if oneShotStr != "" {
		parsed, err := strconv.ParseBool(oneShotStr)
		if err != nil {
			return c.String(http.StatusBadRequest, "Invalid oneShot parameter")
		}
		oneshot = parsed
	}

	// Atomically require the task to exist, then overwrite it:
	if err := upsertSearchTask(id, filter, baseDN, refresh, oneshot, false, true); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	return c.String(http.StatusOK, "Search updated")
}

// deleteSearchHandler godoc
// @Summary Delete search
// @Description Deletes an existing search by its unique id.
// @Tags search
// @Produce json
// @Param id path string true "Unique search id"
// @Success 200 {string} string "Search deleted"
// @Failure 404 {string} string "Search not found"
// @Router /search/{id} [delete]
func deleteSearchHandler(c echo.Context) error {
	id := c.Param("id")

	// Atomically delete from the scheduler
	if err := deleteSearchTask(id); err != nil {
		return c.String(http.StatusNotFound, "Search not found")
	}

	// Clean up stored results
	searchResultsMutex.Lock()
	delete(searchResults, id)
	searchResultsMutex.Unlock()

	return c.String(http.StatusOK, "Search deleted")
}

// getResultsHandler godoc
// @Summary Get search results
// @Description Retrieves all LDAP objects for a given search id.
//
//	If the optional query parameter "full" is true, returns both DN and content; otherwise, only DN is returned.
//
// @Tags results
// @Produce json
// @Param id path string true "Unique search id"
// @Param full query boolean false "Return full result (DN and content) if true, else only DN"
// @Success 200 {array} LDAPResultSimple "When full is false"
// @Success 200 {array} LDAPResult "When full is true"
// @Failure 404 {string} string "Search results not found"
// @Router /results/{id} [get]
func getResultsHandler(c echo.Context) error {
	id := c.Param("id")

	// Acquire read lock while accessing the map
	searchResultsMutex.RLock()
	resultsMap, exists := searchResults[id]
	if !exists {
		searchResultsMutex.RUnlock()
		return c.String(http.StatusNotFound, "Search results not found for id: "+id)
	}

	full, _ := strconv.ParseBool(c.QueryParam("full"))
	if full {
		// Collect full entries under lock
		entries := make([]LDAPResult, 0, len(resultsMap))
		for _, res := range resultsMap {
			entries = append(entries, res)
		}
		searchResultsMutex.RUnlock()
		return c.JSON(http.StatusOK, entries)
	}

	// Collect only DNs under lock
	simple := make([]LDAPResultSimple, 0, len(resultsMap))
	for _, res := range resultsMap {
		simple = append(simple, LDAPResultSimple{DN: res.DN})
	}
	searchResultsMutex.RUnlock()
	return c.JSON(http.StatusOK, simple)
}

// getLogLevelHandler is a REST endpoint that reports the current log level.
// @Summary Get current log level
// @Description Returns the current log level.
// @Tags log
// @Produce json
// @Success 200 {object} map[string]string "current log level"
// @Router /loglevel [get]
func getLogLevelHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"level": currentLogLevel,
	})
}

// logLevelHandler is a REST endpoint to update log level at runtime.
// @Summary Update log level
// @Description Update the logging level at runtime.
// @Tags log
// @Accept json
// @Produce json
// @Param level body LogLevelRequest true "New log level"
// @Success 200 {object} map[string]string "Updated log level"
// @Failure 400 {object} map[string]string "Invalid payload or log level"
// @Router /loglevel [put]
func logLevelHandler(c echo.Context) error {
	type reqBody struct {
		Level string `json:"level"`
	}
	var req reqBody
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to bind log level request", "Err", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid payload",
		})
	}
	newLevel := strings.ToLower(req.Level)
	switch newLevel {
	case "debug", "info", "warn", "error":
		setLogLevel(newLevel)
	default:
		logger.Error("Invalid log level provided", "Level", req.Level)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid log level",
		})
	}
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Log level updated",
		"level":   req.Level,
	})
}

// healthzHandler handles the liveness probe.
// @Summary Liveness Probe
// @Description Returns OK if the application is running.
// @Tags probes
// @Produce json
// @Success 200 {object} map[string]string "status: ok"
// @Router /healthz [get]
func healthzHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// readyzHandler handles the readiness probe.
// @Summary Readiness Probe
// @Description Returns OK if the application is ready to serve traffic.
// @Tags probes
// @Produce json
// @Success 200 {object} map[string]string "status: ready"
// @Router /readyz [get]
func readyzHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
}

// @title ldap-sync API
// @version 1.0
// @description API for synchronizing LDAP entries between two servers.
// @host localhost:5500
// @BasePath /
func main() {
	var loglevel string

	flag.StringVar(&loglevel, "loglevel", "", "Set the log level (debug, info, warn, error)")
	flag.Parse()
	initLogger(loglevel)

	// Load configuration from /etc/ldap-sync/config.yaml.
	if err := loadConfig("/etc/ldap-sync/config.yaml"); err != nil {
		logger.Error("Error loading config", "Err", err)
		os.Exit(1)
	}

	startBackgroundWorkers()

	// Initialize Echo.
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper: func(c echo.Context) bool {
			path := c.Request().URL.Path
			return path == "/healthz" || path == "/readyz"
		},
	}))

	// Register endpoints.
	e.POST("/search", createSearchHandler)
	e.GET("/search", getSearchHandler)
	e.PUT("/search/:id", updateSearchHandler)
	e.DELETE("/search/:id", deleteSearchHandler)
	e.GET("/results/:id", getResultsHandler)
	e.PUT("/loglevel", logLevelHandler)
	e.GET("/loglevel", getLogLevelHandler)
	e.GET("/healthz", healthzHandler)
	e.GET("/readyz", readyzHandler)

	// Redirect /swagger to /swagger/index.html
	e.GET("/swagger", func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
	})

	// Register the Swagger documentation endpoint.
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusFound, "/swagger/index.html")
	})

	logger.Info("Server started on :5500")
	e.Logger.Fatal(e.Start(":5500"))
}
