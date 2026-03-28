package darkscan

import (
	"context"
	"fmt"
	"os"
	"time"

	dsscanner "github.com/afterdarksys/darkscan/pkg/scanner"
)

// FileTypeMiddleware prevents scanning spoofed/dangerous files
type FileTypeMiddleware struct {
	client *Client
}

func (m *FileTypeMiddleware) PreScan(ctx context.Context, path string) ([]*dsscanner.ScanResult, error) {
	if m.client.fileTypeDetector != nil && m.client.config.FileType.DetectSpoofing {
		// Only validate physical files, not memory streams or extracted interior paths
		if _, err := os.Stat(path); err == nil {
			if err := m.client.fileTypeDetector.ValidateBeforeScan(ctx, path, true); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func (m *FileTypeMiddleware) PostScan(ctx context.Context, path string, results []*dsscanner.ScanResult) error {
	return nil
}

// HashStoreMiddleware uses HashStore to deduplicate repeated scans
type HashStoreMiddleware struct {
	client *Client
}

func (m *HashStoreMiddleware) PreScan(ctx context.Context, path string) ([]*dsscanner.ScanResult, error) {
	// Only deduplicate physical files - stat once and cache the result
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil // Stream or extracted file
	}

	if m.client.hashStore != nil && m.client.config.HashStore.DeduplicateScans {
		hash, err := CalculateFileHash(path)
		if err == nil {
			if entry, err := m.client.hashStore.CheckHash(ctx, hash); err == nil && entry != nil {
				retentionDays := m.client.config.HashStore.RetentionDays
				if retentionDays == 0 {
					retentionDays = 90
				}
				if time.Since(entry.LastSeen) < time.Duration(retentionDays)*24*time.Hour {

					// Reconstruct dsscanner.ScanResult
					var threats []dsscanner.Threat
					for _, t := range entry.Threats {
						threats = append(threats, dsscanner.Threat{
							Name:        t.Name,
							Severity:    t.Severity,
							Description: t.Description,
							Engine:      t.Engine,
						})
					}

					return []*dsscanner.ScanResult{
						{
							FilePath:    path,
							Infected:    entry.Infected,
							Threats:     threats,
							ScanEngine:  "HashStore",
						},
					}, nil
				}
			}
		}
	}

	// Memory cache check (backward compatibility) - reuse info from above
	if m.client.config.CacheEnabled {
		cacheKey := path + "_" + info.ModTime().String()
		if val, ok := m.client.cache.Load(cacheKey); ok {
			entry := val.(cacheEntry)
			ttl, parseErr := time.ParseDuration(m.client.config.CacheTTL)
			if parseErr != nil || ttl == 0 {
				ttl = 24 * time.Hour
			}
			if time.Since(entry.Timestamp) < ttl {
				var dsThreats []dsscanner.Threat
				for _, t := range entry.Result.Threats {
					dsThreats = append(dsThreats, dsscanner.Threat{
						Name: t.Name, Severity: t.Severity, Description: t.Description, Engine: t.Engine,
					})
				}

				return []*dsscanner.ScanResult{
					{
						FilePath: path,
						Infected: entry.Result.Infected,
						Threats: dsThreats,
						ScanEngine: "MemoryCache",
					},
				}, nil
			}
			m.client.cache.Delete(cacheKey)
		}
	}

	return nil, nil // Continue scan
}

func (m *HashStoreMiddleware) PostScan(ctx context.Context, path string, results []*dsscanner.ScanResult) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Don't post-process if no results were returned (should never happen here though)
	if len(results) == 0 {
		return nil
	}

	// We only want to cache the fully aggregated result for the root file
	if _, err := os.Stat(path); err != nil {
		return nil
	}

	// Make sure we didn't just retrieve this from cache
	if len(results) == 1 && (results[0].ScanEngine == "HashStore" || results[0].ScanEngine == "MemoryCache") {
		return nil
	}

	aggregated := m.client.aggregateResults(path, results)

	if m.client.hashStore != nil {
		if err := m.client.hashStore.StoreResult(ctx, aggregated); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to store scan result in hash store: %v\n", err)
		}
	}

	if m.client.config.CacheEnabled {
		if info, err := os.Stat(path); err == nil {
			cacheKey := path + "_" + info.ModTime().String()
			m.client.cache.Store(cacheKey, cacheEntry{
				Result:    aggregated,
				Timestamp: time.Now(),
			})
		}
	}

	return nil
}
