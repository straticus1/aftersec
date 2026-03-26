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
	ThreatIntelMatch bool    `json:"threat_intel_match"`
	Source           string  `json:"source,omitempty"` // "filehashes", "darkapi", "local"
}

type Engine struct {
	fileHashesClient *threatintel.FileHashesClient
	darkAPIClient    *threatintel.DarkAPIClient
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

	return engine
}

// Analyze performs multi-layered threat analysis on a binary
func (e *Engine) Analyze(r io.Reader) (*AnalysisResult, error) {
	hasher := sha256.New()
	size, err := io.Copy(hasher, r)
	if err != nil {
		return nil, err
	}
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
