//go:build ignore

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// LoadTestConfig holds configuration for the load test
type LoadTestConfig struct {
	BaseURL         string
	JWTToken        string
	Concurrency     int
	Duration        time.Duration
	RampUpTime      time.Duration
	RequestsPerSec  int
	SkipTLSVerify   bool
	Timeout         time.Duration
}

// LoadTestResult holds metrics from the load test
type LoadTestResult struct {
	TotalRequests    int64
	SuccessRequests  int64
	FailedRequests   int64
	TotalBytes       int64
	MinLatency       time.Duration
	MaxLatency       time.Duration
	AvgLatency       time.Duration
	P50Latency       time.Duration
	P95Latency       time.Duration
	P99Latency       time.Duration
	RequestsPerSec   float64
	BytesPerSec      float64
	ErrorsByCode     map[int]int64
	Latencies        []time.Duration
}

// TestScenario represents a single API test scenario
type TestScenario struct {
	Name        string
	Method      string
	Path        string
	Body        interface{}
	Weight      int // Relative frequency (1-100)
}

var (
	baseURL        = flag.String("url", "https://localhost:8080", "Base URL of API server")
	jwtToken       = flag.String("token", "", "JWT authentication token")
	concurrency    = flag.Int("c", 10, "Number of concurrent workers")
	duration       = flag.Duration("d", 30*time.Second, "Test duration")
	rampUpTime     = flag.Duration("r", 5*time.Second, "Ramp-up time")
	rps            = flag.Int("rps", 0, "Target requests per second (0 = unlimited)")
	skipTLS        = flag.Bool("skip-tls", true, "Skip TLS certificate verification")
	timeout        = flag.Duration("timeout", 30*time.Second, "Request timeout")
	scenarioFilter = flag.String("scenario", "", "Run specific scenario (empty = all)")
)

func main() {
	flag.Parse()

	if *jwtToken == "" {
		log.Fatal("JWT token is required. Use -token flag")
	}

	config := LoadTestConfig{
		BaseURL:        *baseURL,
		JWTToken:       *jwtToken,
		Concurrency:    *concurrency,
		Duration:       *duration,
		RampUpTime:     *rampUpTime,
		RequestsPerSec: *rps,
		SkipTLSVerify:  *skipTLS,
		Timeout:        *timeout,
	}

	log.Printf("🚀 Starting AfterSec Load Test")
	log.Printf("   URL: %s", config.BaseURL)
	log.Printf("   Concurrency: %d workers", config.Concurrency)
	log.Printf("   Duration: %v", config.Duration)
	log.Printf("   Ramp-up: %v", config.RampUpTime)
	if config.RequestsPerSec > 0 {
		log.Printf("   Rate Limit: %d req/s", config.RequestsPerSec)
	} else {
		log.Printf("   Rate Limit: Unlimited")
	}
	log.Println()

	// Define test scenarios
	scenarios := []TestScenario{
		{
			Name:   "Health Check",
			Method: "GET",
			Path:   "/api/v1/health",
			Weight: 10,
		},
		{
			Name:   "List Organizations",
			Method: "GET",
			Path:   "/api/v1/organizations",
			Weight: 20,
		},
		{
			Name:   "List Endpoints",
			Method: "GET",
			Path:   "/api/v1/endpoints",
			Weight: 30,
		},
		{
			Name:   "List Scans",
			Method: "GET",
			Path:   "/api/v1/scans",
			Weight: 25,
		},
		{
			Name:   "Bandit Query",
			Method: "POST",
			Path:   "/api/v1/bandit/query",
			Body: map[string]interface{}{
				"query":       "What processes are running?",
				"include_all": false,
			},
			Weight: 5,
		},
		{
			Name:   "Dark Web Alerts",
			Method: "GET",
			Path:   "/api/v1/darkweb/alerts",
			Weight: 10,
		},
	}

	// Filter scenarios if specified
	if *scenarioFilter != "" {
		filteredScenarios := []TestScenario{}
		for _, s := range scenarios {
			if s.Name == *scenarioFilter {
				filteredScenarios = append(filteredScenarios, s)
			}
		}
		if len(filteredScenarios) == 0 {
			log.Fatalf("Scenario '%s' not found", *scenarioFilter)
		}
		scenarios = filteredScenarios
	}

	// Run load test
	result := runLoadTest(config, scenarios)

	// Print results
	printResults(result)
}

func runLoadTest(config LoadTestConfig, scenarios []TestScenario) *LoadTestResult {
	result := &LoadTestResult{
		ErrorsByCode: make(map[int]int64),
		Latencies:    make([]time.Duration, 0, 10000),
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.SkipTLSVerify,
			},
			MaxIdleConns:        config.Concurrency,
			MaxIdleConnsPerHost: config.Concurrency,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), config.Duration+config.RampUpTime)
	defer cancel()

	// Rate limiter
	var rateLimiter <-chan time.Time
	if config.RequestsPerSec > 0 {
		interval := time.Second / time.Duration(config.RequestsPerSec)
		rateLimiter = time.Tick(interval)
	}

	// Latency tracking
	var latencyMu sync.Mutex

	// Start workers with ramp-up
	workerDelay := time.Duration(0)
	if config.RampUpTime > 0 {
		workerDelay = config.RampUpTime / time.Duration(config.Concurrency)
	}

	startTime := time.Now()

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Ramp-up delay
			if workerDelay > 0 {
				time.Sleep(time.Duration(workerID) * workerDelay)
			}

			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Rate limiting
					if rateLimiter != nil {
						<-rateLimiter
					}

					// Select random scenario based on weight
					scenario := selectScenario(scenarios)

					// Execute request
					latency, statusCode, bytes, err := executeRequest(client, config, scenario)

					atomic.AddInt64(&result.TotalRequests, 1)
					atomic.AddInt64(&result.TotalBytes, int64(bytes))

					if err != nil || statusCode >= 400 {
						atomic.AddInt64(&result.FailedRequests, 1)
						if statusCode > 0 {
							latencyMu.Lock()
							result.ErrorsByCode[statusCode]++
							latencyMu.Unlock()
						}
					} else {
						atomic.AddInt64(&result.SuccessRequests, 1)
					}

					// Record latency
					latencyMu.Lock()
					result.Latencies = append(result.Latencies, latency)
					if result.MinLatency == 0 || latency < result.MinLatency {
						result.MinLatency = latency
					}
					if latency > result.MaxLatency {
						result.MaxLatency = latency
					}
					latencyMu.Unlock()
				}
			}
		}(i)
	}

	// Wait for test to complete
	wg.Wait()
	endTime := time.Now()
	testDuration := endTime.Sub(startTime)

	// Calculate metrics
	calculateMetrics(result, testDuration)

	return result
}

func selectScenario(scenarios []TestScenario) TestScenario {
	totalWeight := 0
	for _, s := range scenarios {
		totalWeight += s.Weight
	}

	// Simple weighted random selection
	r := time.Now().UnixNano() % int64(totalWeight)
	cumulative := int64(0)

	for _, s := range scenarios {
		cumulative += int64(s.Weight)
		if r < cumulative {
			return s
		}
	}

	return scenarios[0]
}

func executeRequest(client *http.Client, config LoadTestConfig, scenario TestScenario) (time.Duration, int, int, error) {
	var body io.Reader
	if scenario.Body != nil {
		jsonBody, _ := json.Marshal(scenario.Body)
		body = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(scenario.Method, config.BaseURL+scenario.Path, body)
	if err != nil {
		return 0, 0, 0, err
	}

	req.Header.Set("Authorization", "Bearer "+config.JWTToken)
	if scenario.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return latency, 0, 0, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	return latency, resp.StatusCode, len(bodyBytes), nil
}

func calculateMetrics(result *LoadTestResult, duration time.Duration) {
	if len(result.Latencies) == 0 {
		return
	}

	// Sort latencies for percentile calculation
	sortLatencies(result.Latencies)

	// Calculate average latency
	var totalLatency time.Duration
	for _, lat := range result.Latencies {
		totalLatency += lat
	}
	result.AvgLatency = totalLatency / time.Duration(len(result.Latencies))

	// Calculate percentiles
	result.P50Latency = result.Latencies[len(result.Latencies)*50/100]
	result.P95Latency = result.Latencies[len(result.Latencies)*95/100]
	result.P99Latency = result.Latencies[len(result.Latencies)*99/100]

	// Calculate throughput
	result.RequestsPerSec = float64(result.TotalRequests) / duration.Seconds()
	result.BytesPerSec = float64(result.TotalBytes) / duration.Seconds()
}

func sortLatencies(latencies []time.Duration) {
	// Simple bubble sort (good enough for testing)
	n := len(latencies)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if latencies[j] > latencies[j+1] {
				latencies[j], latencies[j+1] = latencies[j+1], latencies[j]
			}
		}
	}
}

func printResults(result *LoadTestResult) {
	fmt.Println()
	fmt.Println("=" + repeat("=", 70))
	fmt.Println("  LOAD TEST RESULTS")
	fmt.Println("=" + repeat("=", 70))
	fmt.Println()

	fmt.Printf("Total Requests:      %d\n", result.TotalRequests)
	fmt.Printf("Successful:          %d (%.2f%%)\n", result.SuccessRequests, float64(result.SuccessRequests)/float64(result.TotalRequests)*100)
	fmt.Printf("Failed:              %d (%.2f%%)\n", result.FailedRequests, float64(result.FailedRequests)/float64(result.TotalRequests)*100)
	fmt.Printf("Total Data:          %.2f MB\n", float64(result.TotalBytes)/(1024*1024))
	fmt.Println()

	fmt.Println("Throughput:")
	fmt.Printf("  Requests/sec:      %.2f\n", result.RequestsPerSec)
	fmt.Printf("  Bytes/sec:         %.2f KB/s\n", result.BytesPerSec/1024)
	fmt.Println()

	fmt.Println("Latency:")
	fmt.Printf("  Min:               %v\n", result.MinLatency)
	fmt.Printf("  Max:               %v\n", result.MaxLatency)
	fmt.Printf("  Avg:               %v\n", result.AvgLatency)
	fmt.Printf("  P50 (median):      %v\n", result.P50Latency)
	fmt.Printf("  P95:               %v\n", result.P95Latency)
	fmt.Printf("  P99:               %v\n", result.P99Latency)
	fmt.Println()

	if len(result.ErrorsByCode) > 0 {
		fmt.Println("Errors by Status Code:")
		for code, count := range result.ErrorsByCode {
			fmt.Printf("  %d: %d\n", code, count)
		}
		fmt.Println()
	}

	// Performance assessment
	fmt.Println("Assessment:")
	if result.RequestsPerSec >= 1000 {
		fmt.Println("  ✅ EXCELLENT - System handles >1000 req/s")
	} else if result.RequestsPerSec >= 500 {
		fmt.Println("  ✅ GOOD - System handles 500-1000 req/s")
	} else if result.RequestsPerSec >= 100 {
		fmt.Println("  ⚠️  FAIR - System handles 100-500 req/s")
	} else {
		fmt.Println("  ❌ POOR - System handles <100 req/s")
	}

	if result.P95Latency < 100*time.Millisecond {
		fmt.Println("  ✅ LOW LATENCY - P95 < 100ms")
	} else if result.P95Latency < 500*time.Millisecond {
		fmt.Println("  ⚠️  MODERATE LATENCY - P95 100-500ms")
	} else {
		fmt.Println("  ❌ HIGH LATENCY - P95 > 500ms")
	}

	successRate := float64(result.SuccessRequests) / float64(result.TotalRequests) * 100
	if successRate >= 99.9 {
		fmt.Println("  ✅ EXCELLENT RELIABILITY - >99.9% success")
	} else if successRate >= 99.0 {
		fmt.Println("  ✅ GOOD RELIABILITY - >99% success")
	} else if successRate >= 95.0 {
		fmt.Println("  ⚠️  FAIR RELIABILITY - >95% success")
	} else {
		fmt.Println("  ❌ POOR RELIABILITY - <95% success")
	}

	fmt.Println()
	fmt.Println("=" + repeat("=", 70))
}

func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
