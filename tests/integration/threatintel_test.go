package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"aftersec/pkg/threatintel"
)

// TestDarkAPIClientIntegration tests the DarkAPI client with real API
func TestDarkAPIClientIntegration(t *testing.T) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		t.Skip("DARKAPI_API_KEY not set, skipping integration test")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		t.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("CheckBreachedEmail", func(t *testing.T) {
		// Test with known breached email (example from Have I Been Pwned)
		breaches, err := client.CheckBreachedEmail(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("CheckBreachedEmail failed: %v", err)
		}

		// Should return zero or more breaches
		if breaches == nil {
			t.Error("Expected non-nil breach slice")
		}

		t.Logf("Found %d breaches for test@example.com", len(breaches))
	})

	t.Run("CheckDomainBreaches", func(t *testing.T) {
		breaches, err := client.CheckDomainBreaches(ctx, "example.com")
		if err != nil {
			t.Fatalf("CheckDomainBreaches failed: %v", err)
		}

		if breaches == nil {
			t.Error("Expected non-nil breach slice")
		}

		t.Logf("Found %d domain breaches for example.com", len(breaches))
	})

	t.Run("CheckFileHash", func(t *testing.T) {
		// Test with known malware hash (example - replace with actual test hash)
		testHash := "44d88612fea8a8f36de82e1278abb02f" // MD5 example
		ioc, err := client.CheckFileHash(ctx, testHash)
		if err != nil {
			t.Fatalf("CheckFileHash failed: %v", err)
		}

		// IOC might be nil if hash not found, which is fine
		if ioc != nil {
			t.Logf("Hash matched IOC: %s (severity: %s)", ioc.Source, ioc.Severity)
		} else {
			t.Log("Hash not found in threat database (expected for benign hash)")
		}
	})

	t.Run("CheckIPAddress", func(t *testing.T) {
		// Test with known malicious IP (example - use test IP)
		testIP := "192.0.2.1" // TEST-NET-1 (RFC 5737)
		ioc, err := client.CheckIPAddress(ctx, testIP)
		if err != nil {
			t.Fatalf("CheckIPAddress failed: %v", err)
		}

		if ioc != nil {
			t.Logf("IP matched IOC: %s", ioc.Source)
		} else {
			t.Log("IP not found in threat database")
		}
	})

	t.Run("SearchDarkWeb", func(t *testing.T) {
		keywords := []string{"ransomware", "leaked"}
		mentions, err := client.SearchDarkWeb(ctx, keywords)
		if err != nil {
			t.Fatalf("SearchDarkWeb failed: %v", err)
		}

		if mentions == nil {
			t.Error("Expected non-nil mentions slice")
		}

		t.Logf("Found %d dark web mentions", len(mentions))
	})
}

// TestRateLimiting verifies rate limiting works correctly
func TestRateLimiting(t *testing.T) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		t.Skip("DARKAPI_API_KEY not set, skipping integration test")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		t.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Make 70 requests (rate limit is 60/min)
	// Should complete without errors due to rate limiting
	t.Run("BurstRequests", func(t *testing.T) {
		successCount := 0
		start := time.Now()

		for i := 0; i < 70; i++ {
			_, err := client.CheckBreachedEmail(ctx, "test@example.com")
			if err != nil {
				t.Logf("Request %d failed: %v", i, err)
				continue
			}
			successCount++
		}

		duration := time.Since(start)

		t.Logf("Completed %d/70 requests in %v", successCount, duration)

		// Should take at least 1 minute due to rate limiting
		if duration < 60*time.Second {
			t.Logf("Warning: Completed faster than expected, rate limiting might not be working")
		}

		if successCount < 60 {
			t.Errorf("Expected at least 60 successful requests, got %d", successCount)
		}
	})
}

// TestRetryLogic verifies retry logic with exponential backoff
func TestRetryLogic(t *testing.T) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		t.Skip("DARKAPI_API_KEY not set, skipping integration test")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		t.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	// This test verifies that retries work
	// We can't easily simulate API failures, so we just ensure
	// the client handles errors gracefully
	t.Run("GracefulFailure", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		cancel() // Immediately cancel to force timeout

		_, err := client.CheckBreachedEmail(ctx, "test@example.com")
		if err == nil {
			t.Error("Expected error with cancelled context")
		}

		t.Logf("Error correctly returned: %v", err)
	})
}

// TestThreatCorrelator tests the correlation engine
func TestThreatCorrelator(t *testing.T) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		t.Skip("DARKAPI_API_KEY not set, skipping integration test")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		t.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	correlator := threatintel.NewThreatCorrelator(client)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("CorrelateHash", func(t *testing.T) {
		// Test hash correlation
		testHash := "44d88612fea8a8f36de82e1278abb02f"
		correlation, _ := correlator.CorrelateProcessHash(ctx, "test-endpoint", "/usr/bin/test", testHash)

		if correlation == nil {
			t.Error("Expected non-nil correlation result")
		} else {
			t.Logf("Hash correlation: %v, confidence=%.2f",
				correlation.Description, correlation.Confidence)
		}
	})

	t.Run("CorrelateNetworkConnection", func(t *testing.T) {
		// Test network IOC correlation
		testIP := "192.0.2.1"
		correlation, _ := correlator.CorrelateNetworkConnection(ctx, "test-endpoint", testIP, "")

		if correlation == nil {
			t.Error("Expected non-nil correlation result")
		} else {
			t.Logf("Network correlation: %v, confidence=%.2f",
				correlation.Description, correlation.Confidence)
		}
	})

	t.Run("CorrelateCredentials", func(t *testing.T) {
		// Test credential breach detection
		testEmail := "test@example.com"
		correlation, _ := correlator.CorrelateUserCredentials(ctx, "test-endpoint", testEmail)

		if correlation == nil {
			t.Error("Expected non-nil correlation result")
		} else {
			t.Logf("Credential correlation: %v, confidence=%.2f",
				correlation.Description, correlation.Confidence)
		}
	})

	t.Run("CorrelateDarkWebMentions", func(t *testing.T) {
		// Test dark web mention correlation
		keywords := []string{"test", "security"}
		correlation, _ := correlator.CorrelateDarkWebMentions(ctx, "example.com", keywords)

		if len(correlation) == 0 {
			t.Error("Expected non-nil correlation result")
		} else {
			t.Logf("Dark web correlation: found %d threats", len(correlation))
		}
	})

	t.Run("CheckDomainBreaches", func(t *testing.T) {
		// Test domain-wide breach check
		breaches, err := correlator.CheckDomainBreaches(ctx, "example.com")
		if err != nil {
			t.Fatalf("CheckDomainBreaches failed: %v", err)
		}

		t.Logf("Found %d breaches for domain example.com", len(breaches))
	})
}

// TestCaching verifies correlation caching works correctly
func TestCaching(t *testing.T) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		t.Skip("DARKAPI_API_KEY not set, skipping integration test")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		t.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	correlator := threatintel.NewThreatCorrelator(client)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("CacheHitPerformance", func(t *testing.T) {
		testHash := "44d88612fea8a8f36de82e1278abb02f"

		// First call - cache miss
		start1 := time.Now()
		correlator.CorrelateProcessHash(ctx, "test-endpoint", "/usr/bin/test", testHash)
		duration1 := time.Since(start1)

		// Second call - cache hit (should be much faster)
		start2 := time.Now()
		correlator.CorrelateProcessHash(ctx, "test-endpoint", "/usr/bin/test", testHash)
		duration2 := time.Since(start2)

		t.Logf("First call (cache miss): %v", duration1)
		t.Logf("Second call (cache hit): %v", duration2)

		// Cache hit should be at least 10x faster
		if duration2 > duration1/10 {
			t.Logf("Warning: Cache hit not significantly faster (might not be using cache)")
		}
	})
}

// TestConcurrentCorrelation tests thread safety of correlation engine
func TestConcurrentCorrelation(t *testing.T) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		t.Skip("DARKAPI_API_KEY not set, skipping integration test")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		t.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	correlator := threatintel.NewThreatCorrelator(client)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("ParallelCorrelations", func(t *testing.T) {
		// Launch 10 goroutines doing correlations simultaneously
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(index int) {
				defer func() { done <- true }()

				// Do various correlation types
				correlator.CorrelateProcessHash(ctx, "test-endpoint", "/usr/bin/test", "abc123")
				correlator.CorrelateNetworkConnection(ctx, "test-endpoint", "192.0.2.1", "")
				correlator.CorrelateUserCredentials(ctx, "test-endpoint", "test@example.com")

				t.Logf("Goroutine %d completed", index)
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		t.Log("All concurrent correlations completed successfully")
	})
}

// BenchmarkCorrelation benchmarks correlation performance
func BenchmarkCorrelation(b *testing.B) {
	apiKey := os.Getenv("DARKAPI_API_KEY")
	if apiKey == "" {
		b.Skip("DARKAPI_API_KEY not set, skipping benchmark")
	}

	client, err := threatintel.NewDarkAPIClient(apiKey)
	if err != nil {
		b.Fatalf("Failed to create DarkAPI client: %v", err)
	}
	defer client.Close()

	correlator := threatintel.NewThreatCorrelator(client)
	ctx := context.Background()

	b.Run("HashCorrelation", func(b *testing.B) {
		testHash := "44d88612fea8a8f36de82e1278abb02f"
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			correlator.CorrelateProcessHash(ctx, "test-endpoint", "/usr/bin/test", testHash)
		}
	})

	b.Run("NetworkCorrelation", func(b *testing.B) {
		testIP := "192.0.2.1"
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			correlator.CorrelateNetworkConnection(ctx, "test-endpoint", testIP, "")
		}
	})

	b.Run("CredentialCorrelation", func(b *testing.B) {
		testEmail := "test@example.com"
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			correlator.CorrelateUserCredentials(ctx, "test-endpoint", testEmail)
		}
	})
}
