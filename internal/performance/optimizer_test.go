package performance

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"cli-snitch/monitor"
)

func makeConn(process, addr, port string) *monitor.Connection {
	return &monitor.Connection{
		PID:         1234,
		ProcessName: process,
		User:        "testuser",
		Protocol:    "tcp",
		LocalAddr:   "127.0.0.1",
		LocalPort:   "54321",
		RemoteAddr:  addr,
		RemotePort:  port,
		State:       "ESTABLISHED",
		Timestamp:   time.Now(),
	}
}

// --- ConnectionCache Get/Put ---

func TestConnectionCache_GetPut(t *testing.T) {
	cache := NewConnectionCache(100, 5*time.Minute)

	conn := makeConn("curl", "1.2.3.4", "443")
	cache.Put("key1", conn)

	got, found := cache.Get("key1")
	if !found {
		t.Fatal("expected to find key1 in cache")
	}
	if got.ProcessName != "curl" {
		t.Errorf("expected process 'curl', got '%s'", got.ProcessName)
	}
}

func TestConnectionCache_GetMiss(t *testing.T) {
	cache := NewConnectionCache(100, 5*time.Minute)

	_, found := cache.Get("nonexistent")
	if found {
		t.Error("expected cache miss for nonexistent key")
	}
}

// --- ConnectionCache LRU eviction ---

func TestConnectionCache_LRUEviction(t *testing.T) {
	cache := NewConnectionCache(3, 5*time.Minute)

	cache.Put("a", makeConn("a", "1.1.1.1", "80"))
	cache.Put("b", makeConn("b", "2.2.2.2", "80"))
	cache.Put("c", makeConn("c", "3.3.3.3", "80"))

	// Access "a" so it becomes recently used
	cache.Get("a")

	// This should evict "b" (least recently used)
	cache.Put("d", makeConn("d", "4.4.4.4", "80"))

	if _, found := cache.Get("a"); !found {
		t.Error("'a' should still be in cache (recently accessed)")
	}
	if _, found := cache.Get("d"); !found {
		t.Error("'d' should be in cache (just added)")
	}
	if _, found := cache.Get("c"); !found {
		t.Error("'c' should still be in cache")
	}

	// "b" should have been evicted
	if _, found := cache.Get("b"); found {
		t.Error("'b' should have been evicted")
	}
}

// --- ConnectionCache TTL expiration ---

func TestConnectionCache_TTLExpiration(t *testing.T) {
	cache := NewConnectionCache(100, 50*time.Millisecond)

	cache.Put("expire-me", makeConn("test", "1.1.1.1", "80"))

	// Should be found immediately
	if _, found := cache.Get("expire-me"); !found {
		t.Error("expected to find key before TTL expires")
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	if _, found := cache.Get("expire-me"); found {
		t.Error("expected cache miss after TTL expiration")
	}
}

func TestConnectionCache_CleanupExpired(t *testing.T) {
	cache := NewConnectionCache(100, 50*time.Millisecond)

	cache.Put("a", makeConn("a", "1.1.1.1", "80"))
	cache.Put("b", makeConn("b", "2.2.2.2", "80"))

	time.Sleep(100 * time.Millisecond)

	cleaned := cache.CleanupExpired()
	if cleaned != 2 {
		t.Errorf("expected 2 cleaned entries, got %d", cleaned)
	}
}

// --- ConnectionCache concurrent access ---

func TestConnectionCache_ConcurrentAccess(t *testing.T) {
	cache := NewConnectionCache(1000, 5*time.Minute)

	var wg sync.WaitGroup
	// Writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", i)
			cache.Put(key, makeConn("proc", fmt.Sprintf("10.0.0.%d", i%256), "443"))
		}(i)
	}
	// Readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", i)
			cache.Get(key)
		}(i)
	}

	wg.Wait()

	stats := cache.Stats()
	total := stats["total_connections"].(int)
	if total == 0 {
		t.Error("expected some connections in cache after concurrent writes")
	}
}

// --- FastConnectionMatcher ---

func TestFastConnectionMatcher_IndexAndLookup(t *testing.T) {
	matcher := NewFastConnectionMatcher()

	conn1 := makeConn("curl", "1.2.3.4", "443")
	conn2 := makeConn("curl", "5.6.7.8", "80")
	conn3 := makeConn("wget", "1.2.3.4", "443")

	matcher.IndexConnection(conn1)
	matcher.IndexConnection(conn2)
	matcher.IndexConnection(conn3)

	// Find by process
	curlConns := matcher.FindByProcess("curl")
	if len(curlConns) != 2 {
		t.Errorf("expected 2 curl connections, got %d", len(curlConns))
	}

	wgetConns := matcher.FindByProcess("wget")
	if len(wgetConns) != 1 {
		t.Errorf("expected 1 wget connection, got %d", len(wgetConns))
	}

	// Find by host
	hostConns := matcher.FindByHost("1.2.3.4")
	if len(hostConns) != 2 {
		t.Errorf("expected 2 connections to 1.2.3.4, got %d", len(hostConns))
	}

	// Find by port
	port443 := matcher.FindByPort("443")
	if len(port443) != 2 {
		t.Errorf("expected 2 connections on port 443, got %d", len(port443))
	}

	port80 := matcher.FindByPort("80")
	if len(port80) != 1 {
		t.Errorf("expected 1 connection on port 80, got %d", len(port80))
	}
}

func TestFastConnectionMatcher_EmptyResults(t *testing.T) {
	matcher := NewFastConnectionMatcher()

	results := matcher.FindByProcess("nonexistent")
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}

	results = matcher.FindByHost("255.255.255.255")
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}

	results = matcher.FindByPort("0")
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}

// --- ConnectionProcessor batch processing ---

func TestConnectionProcessor_BatchProcessing(t *testing.T) {
	processor := NewConnectionProcessor(100, 5*time.Minute, 3)

	var processed []*monitor.Connection
	var mu sync.Mutex
	callback := func(c *monitor.Connection) {
		mu.Lock()
		processed = append(processed, c)
		mu.Unlock()
	}

	// Submit 3 connections (batch size), should trigger batch processing
	for i := 0; i < 3; i++ {
		conn := makeConn(fmt.Sprintf("proc%d", i), fmt.Sprintf("10.0.0.%d", i), "443")
		processor.ProcessConnection(conn, callback)
	}

	// Wait briefly for batch goroutines
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := len(processed)
	mu.Unlock()

	if count != 3 {
		t.Errorf("expected 3 processed connections, got %d", count)
	}
}

func TestConnectionProcessor_FlushPendingBatch(t *testing.T) {
	processor := NewConnectionProcessor(100, 5*time.Minute, 10)

	var processed []*monitor.Connection
	var mu sync.Mutex
	callback := func(c *monitor.Connection) {
		mu.Lock()
		processed = append(processed, c)
		mu.Unlock()
	}

	// Submit fewer than batch size
	for i := 0; i < 3; i++ {
		conn := makeConn(fmt.Sprintf("proc%d", i), fmt.Sprintf("10.0.0.%d", i), "443")
		processor.ProcessConnection(conn, callback)
	}

	// Flush remaining
	processor.FlushPendingBatch(callback)

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(processed)
	mu.Unlock()

	if count != 3 {
		t.Errorf("expected 3 flushed connections, got %d", count)
	}
}

func TestConnectionProcessor_CacheHitSkipsCallback(t *testing.T) {
	processor := NewConnectionProcessor(100, 5*time.Minute, 100)

	callbackCount := 0
	var mu sync.Mutex
	callback := func(c *monitor.Connection) {
		mu.Lock()
		callbackCount++
		mu.Unlock()
	}

	conn := makeConn("curl", "1.2.3.4", "443")

	// First call: should process
	processor.ProcessConnection(conn, callback)
	// Second call: same connection, should be cache hit
	processor.ProcessConnection(conn, callback)

	processor.FlushPendingBatch(callback)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	// Only 1 should have been added to batch (second was cache hit)
	if callbackCount != 1 {
		t.Errorf("expected 1 callback (cache hit should skip), got %d", callbackCount)
	}
}

// --- PerformanceOptimizer lifecycle ---

func TestPerformanceOptimizer_Lifecycle(t *testing.T) {
	optimizer := NewPerformanceOptimizer()

	var processed []*monitor.Connection
	var mu sync.Mutex
	callback := func(c *monitor.Connection) {
		mu.Lock()
		processed = append(processed, c)
		mu.Unlock()
	}

	optimizer.StartPeriodicCleanup(100 * time.Millisecond)

	conn := makeConn("firefox", "93.184.216.34", "443")
	optimizer.OptimizeConnection(conn, callback)
	optimizer.FlushAll(callback)

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(processed)
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 processed connection, got %d", count)
	}

	stats := optimizer.GetPerformanceStats()
	if stats == nil {
		t.Error("expected non-nil stats")
	}

	optimizer.StopPeriodicCleanup()
}

func TestPerformanceOptimizer_PeriodicCleanup(t *testing.T) {
	optimizer := NewPerformanceOptimizer()

	// Start and stop should not panic
	optimizer.StartPeriodicCleanup(50 * time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	optimizer.StopPeriodicCleanup()

	// Double stop should not panic
	optimizer.StopPeriodicCleanup()
}
