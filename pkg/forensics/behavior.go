package forensics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ProcessProfile struct {
	ObservedPaths     map[string]bool `json:"observed_paths"`
	MaxNetConnections int             `json:"max_net_connections"`
	RunCount          int             `json:"run_count"`
	FirstSeen         time.Time       `json:"first_seen"`
	LastSeen          time.Time       `json:"last_seen"`
}

type BehaviorDB struct {
	mu       sync.RWMutex
	Profiles map[string]*ProcessProfile `json:"profiles"`
}

var db *BehaviorDB
var dbMu sync.Mutex

func initDB() {
	if db != nil {
		return
	}
	dbMu.Lock()
	defer dbMu.Unlock()
	if db != nil {
		return
	}
	db = &BehaviorDB{
		Profiles: make(map[string]*ProcessProfile),
	}
	LoadBehaviorDB()
}

func getDBPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".aftersec")
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "behavior.json")
}

func LoadBehaviorDB() {
	path := getDBPath()
	data, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(data, db)
	}
	if db.Profiles == nil {
		db.Profiles = make(map[string]*ProcessProfile)
	}
}

func SaveBehaviorDB() {
	initDB()
	db.mu.RLock()
	defer db.mu.RUnlock()
	data, err := json.MarshalIndent(db, "", "  ")
	if err == nil {
		os.WriteFile(getDBPath(), data, 0644)
	}
}

func getKey(cmdStr, path string) string {
	if path != "" {
		return path
	}
	fields := strings.Fields(cmdStr)
	if len(fields) > 0 {
		return fields[0]
	}
	return "unknown"
}

func RecordBehavior(cmdStr, path string, netCount int) {
	initDB()
	db.mu.Lock()
	defer db.mu.Unlock()

	key := getKey(cmdStr, path)
	profile, exists := db.Profiles[key]
	if !exists {
		profile = &ProcessProfile{
			ObservedPaths: make(map[string]bool),
			FirstSeen:     time.Now(),
		}
		db.Profiles[key] = profile
	}

	profile.RunCount++
	profile.LastSeen = time.Now()
	
	if path != "" {
		if profile.ObservedPaths == nil {
			profile.ObservedPaths = make(map[string]bool)
		}
		profile.ObservedPaths[path] = true
	}
	
	if netCount > profile.MaxNetConnections {
		profile.MaxNetConnections = netCount
	}
}

func AnalyzeBehavior(cmdStr, path string, netCount int) (ThreatScore, string) {
	initDB()
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := getKey(cmdStr, path)
	profile, exists := db.Profiles[key]
	if !exists {
		return Safe, ""
	}

	var anomalies []string

	if path != "" && len(profile.ObservedPaths) > 0 && !profile.ObservedPaths[path] {
		anomalies = append(anomalies, "Execution path deviation (never seen here before)")
	}

	if netCount > 0 && profile.MaxNetConnections == 0 {
		anomalies = append(anomalies, "Unexpected network connections (historically offline process)")
	} else if profile.MaxNetConnections > 0 && netCount > profile.MaxNetConnections*3 {
		anomalies = append(anomalies, "Network connection spike (>3x historical maximum)")
	}

	if len(anomalies) > 0 {
		return Suspicious, "Behavioral Anomaly: " + strings.Join(anomalies, "; ")
	}

	return Safe, ""
}
