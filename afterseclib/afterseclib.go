package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"aftersec/pkg/ai"
	"aftersec/pkg/client"
	"aftersec/pkg/core"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/scanners"
	"context"
	"encoding/json"
	"time"
	"unsafe"
)

//export AfterSecLibVersion
func AfterSecLibVersion() *C.char {
	return C.CString("1.0.0")
}

func main() {}

//export RunSecurityScan
func RunSecurityScan() *C.char {
	scanner := scanners.NewMacOSScanner(nil)
	state, err := scanner.Scan(nil)
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}
	data, _ := json.Marshal(state)
	return C.CString(string(data))
}

//export CompareBaselines
func CompareBaselines(latestJSON, currentJSON *C.char) *C.char {
	var latest, current core.SecurityState
	if err := json.Unmarshal([]byte(C.GoString(latestJSON)), &latest); err != nil {
		return C.CString(`{"error": "invalid latest json"}`)
	}
	if err := json.Unmarshal([]byte(C.GoString(currentJSON)), &current); err != nil {
		return C.CString(`{"error": "invalid current json"}`)
	}
	
	diff := core.CompareStates(&latest, &current)
	data, _ := json.Marshal(diff)
	return C.CString(string(data))
}

//export RestoreBaseline
func RestoreBaseline(targetJSON, currentJSON *C.char) *C.char {
	var target, current core.SecurityState
	if err := json.Unmarshal([]byte(C.GoString(targetJSON)), &target); err != nil {
		return C.CString(`{"error": "invalid target json"}`)
	}
	if err := json.Unmarshal([]byte(C.GoString(currentJSON)), &current); err != nil {
		return C.CString(`{"error": "invalid current json"}`)
	}
	cmds, err := core.RestoreToState(&target, &current)
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}
	data, _ := json.Marshal(cmds)
	return C.CString(string(data))
}

//export RegisterAllowedScript
func RegisterAllowedScript(script *C.char) {
	core.RegisterAllowedScript(C.GoString(script))
}

//export RunPrivileged
func RunPrivileged(script *C.char) *C.char {
	err := core.RunPrivileged(C.GoString(script))
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}
	return C.CString(`{"success": true}`)
}

//export InitializeAI
func InitializeAI(provider, model *C.char) *C.char {
	cfg := client.DefaultClientConfig()
	
	prov := C.GoString(provider)
	if prov != "" {
		cfg.Daemon.AI.Provider = prov
	}
	
	mod := C.GoString(model)
	if mod != "" {
		cfg.Daemon.AI.Model = mod
	}
	
	err := ai.InitGenkit(context.Background(), cfg)
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}
	return C.CString(`{"success": true}`)
}

//export AnalyzeThreatEvent
func AnalyzeThreatEvent(eventJSON *C.char) *C.char {
	analysis, err := ai.AnalyzeThreat(context.Background(), C.GoString(eventJSON))
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}
	
	resp := map[string]string{"analysis": analysis}
	data, _ := json.Marshal(resp)
	return C.CString(string(data))
}

//export ScanFileForMalware
func ScanFileForMalware(filePath, configPath *C.char) *C.char {
	path := C.GoString(filePath)
	cfgPath := C.GoString(configPath)

	cfg, err := client.LoadConfig(cfgPath)
	if err != nil {
		cfg = client.DefaultClientConfig()
	}

	if !cfg.Daemon.DarkScan.Enabled {
		return C.CString(`{"error": "DarkScan is disabled"}`)
	}

	var scanner interface {
		ScanWithReport(ctx context.Context, path string) (*darkscan.IntegrationReport, error)
		Close() error
	}

	if cfg.Daemon.DarkScan.UseCLI {
		scanner, err = darkscan.NewCLIClient(&cfg.Daemon.DarkScan, cfg.Daemon.DarkScan.CLIBinaryPath)
	} else {
		scanner, err = darkscan.NewClient(&cfg.Daemon.DarkScan)
	}

	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}
	defer scanner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, err := scanner.ScanWithReport(ctx, path)
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}

	data, _ := json.Marshal(report)
	return C.CString(string(data))
}

//export GetScanHistory
func GetScanHistory(configPath *C.char, limit C.int) *C.char {
	cfgPath := C.GoString(configPath)

	cfg, err := client.LoadConfig(cfgPath)
	if err != nil {
		cfg = client.DefaultClientConfig()
	}

	if !cfg.Daemon.DarkScan.Enabled || !cfg.Daemon.DarkScan.UseCLI {
		return C.CString(`{"error": "History requires DarkScan CLI mode"}`)
	}

	scanner, err := darkscan.NewCLIClient(&cfg.Daemon.DarkScan, cfg.Daemon.DarkScan.CLIBinaryPath)
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	history, err := scanner.History(ctx, int(limit))
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}

	data, _ := json.Marshal(history)
	return C.CString(string(data))
}

//export SearchScanHistory
func SearchScanHistory(query, configPath *C.char, limit C.int) *C.char {
	q := C.GoString(query)
	cfgPath := C.GoString(configPath)

	cfg, err := client.LoadConfig(cfgPath)
	if err != nil {
		cfg = client.DefaultClientConfig()
	}

	if !cfg.Daemon.DarkScan.Enabled || !cfg.Daemon.DarkScan.UseCLI {
		return C.CString(`{"error": "Search requires DarkScan CLI mode"}`)
	}

	scanner, err := darkscan.NewCLIClient(&cfg.Daemon.DarkScan, cfg.Daemon.DarkScan.CLIBinaryPath)
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Search(ctx, q, int(limit))
	if err != nil {
		return C.CString(`{"error": "` + err.Error() + `"}`)
	}

	data, _ := json.Marshal(results)
	return C.CString(string(data))
}

//export FreeString
func FreeString(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}
