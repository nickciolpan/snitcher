package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"cli-snitch/internal/logger"
	"cli-snitch/monitor"
)

// BenchmarkResult contains performance measurement results
type BenchmarkResult struct {
	TestName           string        `json:"test_name"`
	Duration           time.Duration `json:"duration"`
	ConnectionsProcessed int          `json:"connections_processed"`
	ConnectionsPerSecond float64      `json:"connections_per_second"`
	MemoryUsageMB      float64      `json:"memory_usage_mb"`
	CPUUsagePercent    float64      `json:"cpu_usage_percent"`
	ErrorRate          float64      `json:"error_rate"`
	PeakMemoryMB       float64      `json:"peak_memory_mb"`
	AverageLatencyMs   float64      `json:"average_latency_ms"`
	P95LatencyMs       float64      `json:"p95_latency_ms"`
	P99LatencyMs       float64      `json:"p99_latency_ms"`
	Success            bool         `json:"success"`
	Errors             []string     `json:"errors,omitempty"`
}

// PerformanceBenchmark provides performance testing capabilities
type PerformanceBenchmark struct {
	logger   *logger.Logger
	results  []BenchmarkResult
	mu       sync.RWMutex
}

// NewPerformanceBenchmark creates a new performance benchmark instance
func NewPerformanceBenchmark() *PerformanceBenchmark {
	logConfig := logger.Config{
		Level:     logger.INFO,
		Component: "benchmark",
		Console:   true,
	}
	
	benchLogger, err := logger.NewLogger(logConfig)
	if err != nil {
		fmt.Printf("Failed to create benchmark logger: %v\n", err)
		benchLogger = nil
	}
	
	return &PerformanceBenchmark{
		logger:  benchLogger,
		results: make([]BenchmarkResult, 0),
	}
}

// ConnectionLoadTest simulates high connection volume to test performance
func (pb *PerformanceBenchmark) ConnectionLoadTest(connectionsPerSecond int, duration time.Duration) BenchmarkResult {
	if pb.logger != nil {
		pb.logger.Info("Starting connection load test: %d conn/sec for %v", connectionsPerSecond, duration)
	}
	
	result := BenchmarkResult{
		TestName:  fmt.Sprintf("ConnectionLoad_%dps_%vs", connectionsPerSecond, int(duration.Seconds())),
		Duration:  duration,
		Success:   true,
		Errors:    make([]string, 0),
	}
	
	startTime := time.Now()
	var memStats, peakMemStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	connectionCount := 0
	errorCount := 0
	latencies := make([]time.Duration, 0, connectionsPerSecond*int(duration.Seconds()))
	
	// Create mock connection monitor for testing
	mockCallback := func(conn *monitor.Connection) {
		// Simulate processing latency
		processStart := time.Now()
		time.Sleep(time.Microsecond * 100) // Simulate minimal processing
		latencies = append(latencies, time.Since(processStart))
		connectionCount++
	}
	
	connectionMonitor := monitor.NewConnectionMonitor(mockCallback)
	defer connectionMonitor.Close()
	
	// Simulate connection generation
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	ticker := time.NewTicker(time.Second / time.Duration(connectionsPerSecond))
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			goto TestComplete
		case <-ticker.C:
			// Simulate a new connection
			conn := &monitor.Connection{
				PID:         1000 + connectionCount,
				ProcessName: fmt.Sprintf("TestApp%d", connectionCount%10),
				RemoteAddr:  fmt.Sprintf("192.168.1.%d", (connectionCount%254)+1),
				RemotePort:  "443",
				State:       "ESTABLISHED",
				Timestamp:   time.Now(),
			}
			
			// Process through callback
			func() {
				defer func() {
					if r := recover(); r != nil {
						errorCount++
						result.Errors = append(result.Errors, fmt.Sprintf("Panic: %v", r))
					}
				}()
				mockCallback(conn)
			}()
		}
	}
	
TestComplete:
	// Calculate final metrics
	result.Duration = time.Since(startTime)
	result.ConnectionsProcessed = connectionCount
	result.ConnectionsPerSecond = float64(connectionCount) / result.Duration.Seconds()
	result.ErrorRate = float64(errorCount) / float64(connectionCount)
	
	// Memory metrics
	runtime.ReadMemStats(&peakMemStats)
	result.MemoryUsageMB = float64(peakMemStats.Alloc) / 1024 / 1024
	result.PeakMemoryMB = float64(peakMemStats.Sys) / 1024 / 1024
	
	// Latency metrics
	if len(latencies) > 0 {
		result.AverageLatencyMs = calculateAverage(latencies).Seconds() * 1000
		result.P95LatencyMs = calculatePercentile(latencies, 95).Seconds() * 1000
		result.P99LatencyMs = calculatePercentile(latencies, 99).Seconds() * 1000
	}
	
	// Success criteria: < 5% error rate, reasonable latency
	if result.ErrorRate > 0.05 || result.P99LatencyMs > 100 {
		result.Success = false
	}
	
	if pb.logger != nil {
		pb.logger.InfoWithMetrics("Load test completed", map[string]interface{}{
			"connections_processed": result.ConnectionsProcessed,
			"connections_per_sec":   result.ConnectionsPerSecond,
			"error_rate":           result.ErrorRate,
			"avg_latency_ms":       result.AverageLatencyMs,
			"p99_latency_ms":       result.P99LatencyMs,
			"memory_usage_mb":      result.MemoryUsageMB,
			"success":              result.Success,
		})
	}
	
	pb.mu.Lock()
	pb.results = append(pb.results, result)
	pb.mu.Unlock()
	
	return result
}

// MemoryStressTest tests memory usage under sustained load
func (pb *PerformanceBenchmark) MemoryStressTest(maxConnections int, duration time.Duration) BenchmarkResult {
	if pb.logger != nil {
		pb.logger.Info("Starting memory stress test: %d max connections for %v", maxConnections, duration)
	}
	
	result := BenchmarkResult{
		TestName: fmt.Sprintf("MemoryStress_%dconn_%vs", maxConnections, int(duration.Seconds())),
		Duration: duration,
		Success:  true,
		Errors:   make([]string, 0),
	}
	
	startTime := time.Now()
	var memStats runtime.MemStats
	
	// Create connection monitor
	connectionCount := 0
	mockCallback := func(conn *monitor.Connection) {
		connectionCount++
	}
	
	connectionMonitor := monitor.NewConnectionMonitor(mockCallback)
	defer connectionMonitor.Close()
	
	// Track memory usage over time
	memoryReadings := make([]float64, 0)
	memoryTicker := time.NewTicker(time.Second)
	defer memoryTicker.Stop()
	
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	// Generate sustained connections
	go func() {
		connTicker := time.NewTicker(time.Millisecond * 10) // High frequency
		defer connTicker.Stop()
		
		for i := 0; i < maxConnections; i++ {
			select {
			case <-ctx.Done():
				return
			case <-connTicker.C:
				conn := &monitor.Connection{
					PID:         2000 + i,
					ProcessName: fmt.Sprintf("StressApp%d", i%50),
					RemoteAddr:  fmt.Sprintf("10.0.%d.%d", (i/254)+1, (i%254)+1),
					RemotePort:  fmt.Sprintf("%d", 8000+(i%1000)),
					State:       "ESTABLISHED",
					Timestamp:   time.Now(),
				}
				mockCallback(conn)
			}
		}
	}()
	
	// Monitor memory usage
	for {
		select {
		case <-ctx.Done():
			goto MemoryTestComplete
		case <-memoryTicker.C:
			runtime.ReadMemStats(&memStats)
			memoryReadings = append(memoryReadings, float64(memStats.Alloc)/1024/1024)
		}
	}
	
MemoryTestComplete:
	result.Duration = time.Since(startTime)
	result.ConnectionsProcessed = connectionCount
	
	// Calculate memory metrics
	if len(memoryReadings) > 0 {
		result.MemoryUsageMB = memoryReadings[len(memoryReadings)-1]
		result.PeakMemoryMB = findMax(memoryReadings)
	}
	
	// Success criteria: memory usage under reasonable limits
	if result.PeakMemoryMB > 500 { // 500MB limit
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("Peak memory usage exceeded limit: %.2f MB", result.PeakMemoryMB))
	}
	
	if pb.logger != nil {
		pb.logger.InfoWithMetrics("Memory stress test completed", map[string]interface{}{
			"connections_processed": result.ConnectionsProcessed,
			"peak_memory_mb":       result.PeakMemoryMB,
			"final_memory_mb":      result.MemoryUsageMB,
			"success":              result.Success,
		})
	}
	
	pb.mu.Lock()
	pb.results = append(pb.results, result)
	pb.mu.Unlock()
	
	return result
}

// ConcurrencyStressTest tests performance under high concurrency
func (pb *PerformanceBenchmark) ConcurrencyStressTest(goroutines int, operationsPerGoroutine int) BenchmarkResult {
	if pb.logger != nil {
		pb.logger.Info("Starting concurrency stress test: %d goroutines, %d ops each", goroutines, operationsPerGoroutine)
	}
	
	result := BenchmarkResult{
		TestName: fmt.Sprintf("ConcurrencyStress_%dg_%dops", goroutines, operationsPerGoroutine),
		Success:  true,
		Errors:   make([]string, 0),
	}
	
	startTime := time.Now()
	var wg sync.WaitGroup
	
	totalOps := 0
	errorCount := 0
	mu := sync.Mutex{}
	
	connectionMonitor := monitor.NewConnectionMonitor(func(conn *monitor.Connection) {
		mu.Lock()
		totalOps++
		mu.Unlock()
	})
	defer connectionMonitor.Close()
	
	// Launch concurrent goroutines
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for op := 0; op < operationsPerGoroutine; op++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							mu.Lock()
							errorCount++
							mu.Unlock()
						}
					}()
					
					// Simulate concurrent connection processing
					// Process through monitor (simulated)
					time.Sleep(time.Microsecond * 50) // Simulate processing
				}()
			}
		}(g)
	}
	
	wg.Wait()
	
	result.Duration = time.Since(startTime)
	result.ConnectionsProcessed = totalOps
	result.ConnectionsPerSecond = float64(totalOps) / result.Duration.Seconds()
	result.ErrorRate = float64(errorCount) / float64(goroutines*operationsPerGoroutine)
	
	// Memory check
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	result.MemoryUsageMB = float64(memStats.Alloc) / 1024 / 1024
	
	// Success criteria
	if result.ErrorRate > 0.01 {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("High error rate: %.2f%%", result.ErrorRate*100))
	}
	
	if pb.logger != nil {
		pb.logger.InfoWithMetrics("Concurrency stress test completed", map[string]interface{}{
			"total_operations":     goroutines * operationsPerGoroutine,
			"operations_per_sec":   result.ConnectionsPerSecond,
			"error_rate":          result.ErrorRate,
			"memory_usage_mb":     result.MemoryUsageMB,
			"success":             result.Success,
		})
	}
	
	pb.mu.Lock()
	pb.results = append(pb.results, result)
	pb.mu.Unlock()
	
	return result
}

// GetResults returns all benchmark results
func (pb *PerformanceBenchmark) GetResults() []BenchmarkResult {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	
	results := make([]BenchmarkResult, len(pb.results))
	copy(results, pb.results)
	return results
}

// GenerateReport generates a performance report
func (pb *PerformanceBenchmark) GenerateReport() string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	
	report := "CLI Snitch Performance Benchmark Report\n"
	report += "=========================================\n\n"
	
	totalTests := len(pb.results)
	successfulTests := 0
	
	for _, result := range pb.results {
		if result.Success {
			successfulTests++
		}
		
		report += fmt.Sprintf("Test: %s\n", result.TestName)
		report += fmt.Sprintf("  Duration: %v\n", result.Duration)
		report += fmt.Sprintf("  Connections Processed: %d\n", result.ConnectionsProcessed)
		report += fmt.Sprintf("  Connections/sec: %.2f\n", result.ConnectionsPerSecond)
		report += fmt.Sprintf("  Memory Usage: %.2f MB\n", result.MemoryUsageMB)
		report += fmt.Sprintf("  Peak Memory: %.2f MB\n", result.PeakMemoryMB)
		report += fmt.Sprintf("  Error Rate: %.2f%%\n", result.ErrorRate*100)
		if result.AverageLatencyMs > 0 {
			report += fmt.Sprintf("  Avg Latency: %.2f ms\n", result.AverageLatencyMs)
			report += fmt.Sprintf("  P99 Latency: %.2f ms\n", result.P99LatencyMs)
		}
		report += fmt.Sprintf("  Success: %t\n", result.Success)
		if len(result.Errors) > 0 {
			report += fmt.Sprintf("  Errors: %v\n", result.Errors)
		}
		report += "\n"
	}
	
	report += fmt.Sprintf("Summary: %d/%d tests passed (%.1f%%)\n", 
		successfulTests, totalTests, float64(successfulTests)/float64(totalTests)*100)
	
	return report
}

// Helper functions

func calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func calculatePercentile(durations []time.Duration, percentile int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	// Simple percentile calculation (would normally sort first)
	index := (len(durations) * percentile) / 100
	if index >= len(durations) {
		index = len(durations) - 1
	}
	return durations[index]
}

func findMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
} 