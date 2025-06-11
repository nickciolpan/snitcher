package performance

import (
	"sync"
	"time"

	"cli-snitch/internal/logger"
	"cli-snitch/monitor"
)

// ConnectionCache provides connection tracking with efficient lookups
type ConnectionCache struct {
	connections map[string]*CachedConnection
	mu          sync.RWMutex
	maxSize     int
	ttl         time.Duration
	logger      *logger.Logger
}

// CachedConnection wraps a connection with caching metadata
type CachedConnection struct {
	*monitor.Connection
	LastAccessed time.Time
	AccessCount  int
}

// NewConnectionCache creates a connection cache
func NewConnectionCache(maxSize int, ttl time.Duration) *ConnectionCache {
	logConfig := logger.Config{
		Level:     logger.DEBUG,
		Component: "cache",
		Console:   true,
	}
	
	cacheLogger, err := logger.NewLogger(logConfig)
	if err != nil {
		cacheLogger = nil
	}
	
	return &ConnectionCache{
		connections: make(map[string]*CachedConnection),
		maxSize:     maxSize,
		ttl:         ttl,
		logger:      cacheLogger,
	}
}

// Get retrieves a connection from cache with O(1) lookup
func (cc *ConnectionCache) Get(key string) (*monitor.Connection, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	
	cached, exists := cc.connections[key]
	if !exists {
		return nil, false
	}
	
	// Check TTL
	if time.Since(cached.LastAccessed) > cc.ttl {
		// Don't remove here to avoid write lock, will be cleaned up later
		return nil, false
	}
	
	// Update access info (this is safe in read lock since we're modifying the cached object)
	cached.LastAccessed = time.Now()
	cached.AccessCount++
	
	return cached.Connection, true
}

// Put stores a connection in cache with LRU eviction
func (cc *ConnectionCache) Put(key string, conn *monitor.Connection) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	// Check if we need to evict
	if len(cc.connections) >= cc.maxSize {
		cc.evictLRU()
	}
	
	cached := &CachedConnection{
		Connection:   conn,
		LastAccessed: time.Now(),
		AccessCount:  1,
	}
	
	cc.connections[key] = cached
	
	if cc.logger != nil {
		cc.logger.Debug("Cached connection: %s (total: %d)", key, len(cc.connections))
	}
}

// evictLRU removes the least recently used connection
func (cc *ConnectionCache) evictLRU() {
	if len(cc.connections) == 0 {
		return
	}
	
	var oldestKey string
	var oldestTime time.Time
	
	for key, cached := range cc.connections {
		if oldestKey == "" || cached.LastAccessed.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.LastAccessed
		}
	}
	
	if oldestKey != "" {
		delete(cc.connections, oldestKey)
		if cc.logger != nil {
			cc.logger.Debug("Evicted LRU connection: %s", oldestKey)
		}
	}
}

// CleanupExpired removes expired connections
func (cc *ConnectionCache) CleanupExpired() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	now := time.Now()
	cleaned := 0
	
	for key, cached := range cc.connections {
		if now.Sub(cached.LastAccessed) > cc.ttl {
			delete(cc.connections, key)
			cleaned++
		}
	}
	
	if cc.logger != nil && cleaned > 0 {
		cc.logger.Debug("Cleaned up %d expired connections", cleaned)
	}
	
	return cleaned
}

// Stats returns cache statistics
func (cc *ConnectionCache) Stats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	
	return map[string]interface{}{
		"total_connections": len(cc.connections),
		"max_size":         cc.maxSize,
		"ttl_seconds":      cc.ttl.Seconds(),
		"utilization":      float64(len(cc.connections)) / float64(cc.maxSize),
	}
}

// FastConnectionMatcher provides connection matching algorithms
type FastConnectionMatcher struct {
	processIndex  map[string][]*monitor.Connection
	hostIndex     map[string][]*monitor.Connection
	portIndex     map[string][]*monitor.Connection
	mu            sync.RWMutex
	logger        *logger.Logger
}

// NewFastConnectionMatcher creates a connection matcher
func NewFastConnectionMatcher() *FastConnectionMatcher {
	logConfig := logger.Config{
		Level:     logger.DEBUG,
		Component: "matcher",
		Console:   true,
	}
	
	matcherLogger, err := logger.NewLogger(logConfig)
	if err != nil {
		matcherLogger = nil
	}
	
	return &FastConnectionMatcher{
		processIndex: make(map[string][]*monitor.Connection),
		hostIndex:    make(map[string][]*monitor.Connection),
		portIndex:    make(map[string][]*monitor.Connection),
		logger:       matcherLogger,
	}
}

// IndexConnection adds a connection to the optimized indexes
func (fcm *FastConnectionMatcher) IndexConnection(conn *monitor.Connection) {
	fcm.mu.Lock()
	defer fcm.mu.Unlock()
	
	// Index by process name
	fcm.processIndex[conn.ProcessName] = append(fcm.processIndex[conn.ProcessName], conn)
	
	// Index by remote host
	fcm.hostIndex[conn.RemoteAddr] = append(fcm.hostIndex[conn.RemoteAddr], conn)
	
	// Index by remote port
	fcm.portIndex[conn.RemotePort] = append(fcm.portIndex[conn.RemotePort], conn)
	
	if fcm.logger != nil {
		fcm.logger.Debug("Indexed connection: %s -> %s:%s", conn.ProcessName, conn.RemoteAddr, conn.RemotePort)
	}
}

// FindByProcess efficiently finds connections by process name - O(1) lookup
func (fcm *FastConnectionMatcher) FindByProcess(processName string) []*monitor.Connection {
	fcm.mu.RLock()
	defer fcm.mu.RUnlock()
	
	connections := fcm.processIndex[processName]
	if connections == nil {
		return []*monitor.Connection{}
	}
	
	// Return a copy to avoid race conditions
	result := make([]*monitor.Connection, len(connections))
	copy(result, connections)
	return result
}

// FindByHost efficiently finds connections by host - O(1) lookup
func (fcm *FastConnectionMatcher) FindByHost(host string) []*monitor.Connection {
	fcm.mu.RLock()
	defer fcm.mu.RUnlock()
	
	connections := fcm.hostIndex[host]
	if connections == nil {
		return []*monitor.Connection{}
	}
	
	result := make([]*monitor.Connection, len(connections))
	copy(result, connections)
	return result
}

// FindByPort efficiently finds connections by port - O(1) lookup
func (fcm *FastConnectionMatcher) FindByPort(port string) []*monitor.Connection {
	fcm.mu.RLock()
	defer fcm.mu.RUnlock()
	
	connections := fcm.portIndex[port]
	if connections == nil {
		return []*monitor.Connection{}
	}
	
	result := make([]*monitor.Connection, len(connections))
	copy(result, connections)
	return result
}

// ConnectionProcessor provides connection processing
type ConnectionProcessor struct {
	cache         *ConnectionCache
	matcher       *FastConnectionMatcher
	processPool   *sync.Pool
	batchSize     int
	batchTimeout  time.Duration
	pendingBatch  []*monitor.Connection
	batchMu       sync.Mutex
	logger        *logger.Logger
}

// NewConnectionProcessor creates a connection processor
func NewConnectionProcessor(cacheSize int, cacheTTL time.Duration, batchSize int) *ConnectionProcessor {
	logConfig := logger.Config{
		Level:     logger.INFO,
		Component: "processor",
		Console:   true,
	}
	
	processorLogger, err := logger.NewLogger(logConfig)
	if err != nil {
		processorLogger = nil
	}
	
	// Object pool for reusing connection processing contexts
	processPool := &sync.Pool{
		New: func() interface{} {
			return &ProcessingContext{
				Metrics: make(map[string]interface{}),
			}
		},
	}
	
	return &ConnectionProcessor{
		cache:        NewConnectionCache(cacheSize, cacheTTL),
		matcher:      NewFastConnectionMatcher(),
		processPool:  processPool,
		batchSize:    batchSize,
		batchTimeout: time.Millisecond * 100,
		pendingBatch: make([]*monitor.Connection, 0, batchSize),
		logger:       processorLogger,
	}
}

// ProcessingContext provides reusable context for connection processing
type ProcessingContext struct {
	StartTime time.Time
	Metrics   map[string]interface{}
}

// ProcessConnection processes a connection
func (ocp *ConnectionProcessor) ProcessConnection(conn *monitor.Connection, callback func(*monitor.Connection)) {
	startTime := time.Now()
	
	// Get processing context from pool
	ctx := ocp.processPool.Get().(*ProcessingContext)
	ctx.StartTime = startTime
	defer func() {
		// Clear metrics map and return to pool
		for k := range ctx.Metrics {
			delete(ctx.Metrics, k)
		}
		ocp.processPool.Put(ctx)
	}()
	
	// Check cache first for O(1) lookup
	connKey := ocp.generateConnectionKey(conn)
	if _, found := ocp.cache.Get(connKey); found {
		// Connection already processed recently
		ctx.Metrics["cache_hit"] = true
		ctx.Metrics["processing_time_ns"] = time.Since(startTime).Nanoseconds()
		
		if ocp.logger != nil {
			ocp.logger.Debug("Cache hit for connection: %s", connKey)
		}
		return
	}
	
	// Add to cache for future lookups
	ocp.cache.Put(connKey, conn)
	
	// Index for fast searching
	ocp.matcher.IndexConnection(conn)
	
	// Add to batch processing queue
	ocp.addToBatch(conn, callback)
	
	ctx.Metrics["cache_hit"] = false
	ctx.Metrics["processing_time_ns"] = time.Since(startTime).Nanoseconds()
	
	if ocp.logger != nil {
		ocp.logger.Debug("Processed new connection: %s (time: %dns)", 
			connKey, ctx.Metrics["processing_time_ns"])
	}
}

// addToBatch adds connection to batch processing queue
func (ocp *ConnectionProcessor) addToBatch(conn *monitor.Connection, callback func(*monitor.Connection)) {
	ocp.batchMu.Lock()
	defer ocp.batchMu.Unlock()
	
	ocp.pendingBatch = append(ocp.pendingBatch, conn)
	
	// Process batch if it's full
	if len(ocp.pendingBatch) >= ocp.batchSize {
		ocp.processBatch(callback)
	}
}

// processBatch processes a batch of connections efficiently
func (ocp *ConnectionProcessor) processBatch(callback func(*monitor.Connection)) {
	if len(ocp.pendingBatch) == 0 {
		return
	}
	
	batch := make([]*monitor.Connection, len(ocp.pendingBatch))
	copy(batch, ocp.pendingBatch)
	ocp.pendingBatch = ocp.pendingBatch[:0] // Reset slice
	
	if ocp.logger != nil {
		ocp.logger.Debug("Processing batch of %d connections", len(batch))
	}
	
	// Process batch concurrently
	var wg sync.WaitGroup
	for _, conn := range batch {
		wg.Add(1)
		go func(c *monitor.Connection) {
			defer wg.Done()
			callback(c)
		}(conn)
	}
	wg.Wait()
}

// FlushPendingBatch processes any remaining connections in the batch
func (ocp *ConnectionProcessor) FlushPendingBatch(callback func(*monitor.Connection)) {
	ocp.batchMu.Lock()
	defer ocp.batchMu.Unlock()
	
	if len(ocp.pendingBatch) > 0 {
		ocp.processBatch(callback)
	}
}

// generateConnectionKey creates a connection key
func (ocp *ConnectionProcessor) generateConnectionKey(conn *monitor.Connection) string {
	// Pre-allocate string builder with estimated capacity
	return conn.ProcessName + ":" + conn.RemoteAddr + ":" + conn.RemotePort
}

// GetStats returns processor statistics
func (ocp *ConnectionProcessor) GetStats() map[string]interface{} {
	ocp.batchMu.Lock()
	pendingCount := len(ocp.pendingBatch)
	ocp.batchMu.Unlock()
	
	stats := map[string]interface{}{
		"pending_batch_size": pendingCount,
		"batch_size_limit":   ocp.batchSize,
		"batch_timeout_ms":   ocp.batchTimeout.Milliseconds(),
	}
	
	// Add cache stats
	cacheStats := ocp.cache.Stats()
	for k, v := range cacheStats {
		stats["cache_"+k] = v
	}
	
	return stats
}

// Cleanup performs maintenance operations
func (ocp *ConnectionProcessor) Cleanup() {
	if ocp.logger != nil {
		ocp.logger.Debug("Starting processor cleanup")
	}
	
	// Cleanup expired cache entries
	cleaned := ocp.cache.CleanupExpired()
	
	if ocp.logger != nil {
		ocp.logger.Debug("Cleanup completed: removed %d expired entries", cleaned)
	}
}

// PerformanceOptimizer provides system-wide performance optimizations
type PerformanceOptimizer struct {
	processor    *ConnectionProcessor
	cleanupTimer *time.Timer
	logger       *logger.Logger
}

// NewPerformanceOptimizer creates a performance optimizer
func NewPerformanceOptimizer() *PerformanceOptimizer {
	logConfig := logger.Config{
		Level:     logger.INFO,
		Component: "optimizer",
		Console:   true,
	}
	
	optimizerLogger, err := logger.NewLogger(logConfig)
	if err != nil {
		optimizerLogger = nil
	}
	
	// Create processor with tuned parameters
	processor := NewConnectionProcessor(
		10000,              // Cache size
		5*time.Minute,      // Cache TTL
		100,                // Batch size
	)
	
	return &PerformanceOptimizer{
		processor: processor,
		logger:    optimizerLogger,
	}
}

// OptimizeConnection processes a connection with all optimizations enabled
func (po *PerformanceOptimizer) OptimizeConnection(conn *monitor.Connection, callback func(*monitor.Connection)) {
	po.processor.ProcessConnection(conn, callback)
}

// StartPeriodicCleanup starts background maintenance
func (po *PerformanceOptimizer) StartPeriodicCleanup(interval time.Duration) {
	if po.cleanupTimer != nil {
		po.cleanupTimer.Stop()
	}
	
	po.cleanupTimer = time.AfterFunc(interval, func() {
		po.processor.Cleanup()
		po.StartPeriodicCleanup(interval) // Reschedule
	})
	
	if po.logger != nil {
		po.logger.Info("Started periodic cleanup with %v interval", interval)
	}
}

// StopPeriodicCleanup stops background maintenance
func (po *PerformanceOptimizer) StopPeriodicCleanup() {
	if po.cleanupTimer != nil {
		po.cleanupTimer.Stop()
		po.cleanupTimer = nil
	}
	
	if po.logger != nil {
		po.logger.Info("Stopped periodic cleanup")
	}
}

// GetPerformanceStats returns performance statistics
func (po *PerformanceOptimizer) GetPerformanceStats() map[string]interface{} {
	return po.processor.GetStats()
}

// FlushAll flushes pending operations
func (po *PerformanceOptimizer) FlushAll(callback func(*monitor.Connection)) {
	po.processor.FlushPendingBatch(callback)
} 