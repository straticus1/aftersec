package detonation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"aftersec/pkg/threatintel"
	"aftersec/pkg/forensics"
	"aftersec/pkg/darkscan"
)

type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictDeny  Verdict = "DENY"
)

type AnalysisResult struct {
	Hash             string  `json:"hash"`
	Verdict          Verdict `json:"verdict"`
	Score            int     `json:"score"`
	ThreatIntelMatch bool     `json:"threat_intel_match"`
	Source           string   `json:"source,omitempty"` // "filehashes", "darkapi", "local"
	FlossStrings     []string `json:"floss_strings,omitempty"`
	DarkScanThreats  []string `json:"darkscan_threats,omitempty"`
}

type Engine struct {
	fileHashesClient *threatintel.FileHashesClient
	darkAPIClient    *threatintel.DarkAPIClient
	dsClient         *darkscan.Client
}

func NewEngine() *Engine {
	engine := &Engine{}

	// Initialize FileHashes.io client if API key is configured
	if fileHashesAPIKey := os.Getenv("FILEHASHES_API_KEY"); fileHashesAPIKey != "" {
		engine.fileHashesClient = threatintel.NewFileHashesClient(fileHashesAPIKey)
		log.Println("✅ [DETONATION] FileHashes.io global threat intelligence enabled")
	}

	// Initialize DarkAPI client if API key is configured
	if darkAPIKey := os.Getenv("DARKAPI_API_KEY"); darkAPIKey != "" {
		client, err := threatintel.NewDarkAPIClient(darkAPIKey)
		if err == nil {
			engine.darkAPIClient = client
			log.Println("✅ [DETONATION] DarkAPI.io threat intelligence enabled")
		}
	}

	// Initialize DarkScan Multi-Engine for local detonation
	// In a real enterprise deployment, these paths would be pulled from server config.
	dsc, err := darkscan.NewClient(darkscan.DefaultConfig())
	if err == nil {
		engine.dsClient = dsc
		log.Println("✅ [DETONATION] DarkScan Local Engine initialized (ClamAV/YARA/CAPA)")
	} else {
		log.Printf("⚠️ [DETONATION] DarkScan failed to initialize: %v", err)
	}

	return engine
}

// Analyze performs multi-layered threat analysis on a binary
func (e *Engine) Analyze(r io.Reader) (*AnalysisResult, error) {
	tmpFile, err := os.CreateTemp("", "detonation-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	hasher := sha256.New()
	mw := io.MultiWriter(hasher, tmpFile)

	size, err := io.Copy(mw, r)
	if err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	hashStr := hex.EncodeToString(hasher.Sum(nil))

	result := &AnalysisResult{
		Hash:    hashStr,
		Verdict: VerdictAllow,
		Score:   0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Phase 1: FileHashes.io Global Threat Intelligence (fastest)
	if e.fileHashesClient != nil {
		record, err := e.fileHashesClient.LookupHash(ctx, hashStr)
		if err == nil && record != nil {
			log.Printf("📊 [FILEHASHES] Hash found in global database: %s (ThreatLevel: %d, SeenTimes: %d)",
				hashStr[:16], record.ThreatLevel, record.SeenTimes)

			// Threat level 7+ = critical threat
			if record.ThreatLevel >= 7 {
				result.Verdict = VerdictDeny
				result.Score = record.ThreatLevel * 10
				result.ThreatIntelMatch = true
				result.Source = "filehashes"
				log.Printf("🛑 [FILEHASHES] BLOCKED: Hash %s marked as malicious (ThreatLevel: %d)",
					hashStr[:16], record.ThreatLevel)
				return result, nil
			}

			// Threat level 4-6 = suspicious, increase score but don't block
			if record.ThreatLevel >= 4 {
				result.Score = record.ThreatLevel * 10
				result.ThreatIntelMatch = true
				result.Source = "filehashes"
			}
		} else if err != nil {
			log.Printf("⚠️ [FILEHASHES] Lookup failed: %v", err)
		}
	}

	// Phase 2: DarkAPI.io Hash Reputation Check
	if e.darkAPIClient != nil && result.Verdict == VerdictAllow {
		ioc, err := e.darkAPIClient.CheckFileHash(ctx, hashStr)
		if err == nil && ioc != nil && ioc.Severity == "critical" {
			result.Verdict = VerdictDeny
			result.Score = 90
			result.ThreatIntelMatch = true
			result.Source = "darkapi"
			log.Printf("🛑 [DARKAPI] BLOCKED: Hash %s found in dark web threat feeds", hashStr[:16])
			return result, nil
		}
	}

	// Phase 3: Local Heuristics (stub - extend with sandbox integration)
	if size == 666 {
		result.Verdict = VerdictDeny
		result.Score = 100
		result.Source = "local"
		log.Printf("🛑 [LOCAL] BLOCKED: Suspicious binary size: %d bytes", size)
	}

	// Phase 4: FLOSS String Deobfuscation
	if forensics.IsFlossInstalled() {
		flossCtx, flossCancel := context.WithTimeout(ctx, 3*time.Minute)
		defer flossCancel()
		
		flossRes, err := forensics.ExtractFLOSS(flossCtx, tmpFile.Name())
		if err == nil && flossRes != nil {
			log.Printf("🧬 [FLOSS] Deobfuscated strings extracted for %s", hashStr[:16])
			result.FlossStrings = append(result.FlossStrings, flossRes.DecodedStrings...)
			result.FlossStrings = append(result.FlossStrings, flossRes.StackStrings...)
			result.FlossStrings = append(result.FlossStrings, flossRes.TightStrings...)
		}
	}

	// Phase 4.5: Microscopic CPU Sandbox (Unicorn)
	emuCtx, emuCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer emuCancel()
	
	emuRes, err := forensics.EmulateMachO(emuCtx, tmpFile.Name())
	if err == nil && emuRes != nil {
		log.Printf("🦄 [EMULATOR] Mapped Mach-O and emulated %d instructions (Syscalls: %d, Loops: %d)", 
			emuRes.Instructions, emuRes.Syscalls, emuRes.UnpackingLoops)
		
		if emuRes.Score >= 50 {
			result.Verdict = VerdictDeny
			result.Score = 100
			result.Source = "unicorn"
			log.Printf("🛑 [EMULATOR] BLOCKED: High-entropy execution behavior detected (Score: %d)", emuRes.Score)
		} else if emuRes.Score >= 20 {
			result.Score += emuRes.Score
		}
	} else if err != nil {
		// Log but don't fail detonation if binary is not Mach-O or Unicorn crashes
		log.Printf("ℹ️ [EMULATOR] Sandbox execution skipped/failed: %v", err)
	}

	// Phase 5: DarkScan Multi-Engine (ClamAV/YARA/CAPA)
	if e.dsClient != nil && result.Verdict == VerdictAllow {
		dsCtx, dsCancel := context.WithTimeout(ctx, 45*time.Second)
		defer dsCancel()
		
		scanRes, err := e.dsClient.ScanFile(dsCtx, tmpFile.Name())
		if err == nil && scanRes != nil && scanRes.Infected {
			result.Verdict = VerdictDeny
			result.Score = 100
			result.Source = "darkscan"
			for _, t := range scanRes.Threats {
				threatStr := fmt.Sprintf("[%s] %s", t.Engine, t.Name)
				result.DarkScanThreats = append(result.DarkScanThreats, threatStr)
			}
			log.Printf("🛑 [DARKSCAN] BLOCKED: Found %d malicious signatures in %s", len(scanRes.Threats), hashStr[:16])
		}
	}

	if result.Verdict == VerdictAllow {
		log.Printf("✅ [DETONATION] Binary allowed: %s (Score: %d)", hashStr[:16], result.Score)
	}

	return result, nil
}

// SubmitToGlobalIntel submits hash metadata to FileHashes.io for global tracking
func (e *Engine) SubmitToGlobalIntel(ctx context.Context, hash string, threatLevel int, signed bool, fileName string, fileSize int64, detectedBy string) error {
	if e.fileHashesClient == nil {
		return fmt.Errorf("FileHashes.io client not configured")
	}

	// Get geolocation for submission metadata
	geo, err := threatintel.GetGeoLocation(ctx)
	if err != nil {
		log.Printf("⚠️ [GEOLOCATION] Failed to get location: %v, using fallback", err)
		geo = threatintel.GetGeoLocationFallback()
	}

	submission := &threatintel.HashSubmission{
		Hash:             hash,
		Algorithm:        "sha256",
		ThreatLevel:      threatLevel,
		SignedStatus:     signed,
		SubmittedCountry: geo.Country,
		SubmittedState:   geo.State,
		SubmittedISP:     geo.ISP,
		FileSize:         fileSize,
		FileName:         fileName,
		DetectedBy:       detectedBy,
		Timestamp:        time.Now(),
	}

	if err := e.fileHashesClient.SubmitHash(ctx, submission); err != nil {
		return fmt.Errorf("failed to submit hash: %w", err)
	}

	log.Printf("📤 [FILEHASHES] Submitted hash %s to global database (ThreatLevel: %d, Country: %s)",
		hash[:16], threatLevel, geo.Country)

	return nil
}
