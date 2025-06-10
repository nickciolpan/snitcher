package monitor

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cli-snitch/internal/errors"
	"cli-snitch/internal/logger"
)

// Connection represents a network connection detected by the monitor
type Connection struct {
	PID         int       `json:"pid"`
	ProcessName string    `json:"process_name"`
	User        string    `json:"user"`
	Protocol    string    `json:"protocol"`
	LocalAddr   string    `json:"local_addr"`
	LocalPort   string    `json:"local_port"`
	RemoteAddr  string    `json:"remote_addr"`
	RemotePort  string    `json:"remote_port"`
	State       string    `json:"state"`
	Timestamp   time.Time `json:"timestamp"`
}

// ConnectionMonitor tracks network connections and detects new outbound connections
type ConnectionMonitor struct {
	connections        map[string]*Connection
	newConnCallback    func(*Connection)
	lastCleanup        time.Time
	connectionCount    int
	maxConnections     int
	logger             *logger.Logger
	errorHandler       *errors.ErrorHandler
	recoveryManager    *errors.RecoveryManager
	consecutiveErrors  int
	maxConsecutiveErrs int
}

// NewConnectionMonitor creates a new connection monitor
func NewConnectionMonitor(callback func(*Connection)) *ConnectionMonitor {
	// Initialize logger for monitor component
	logConfig := logger.Config{
		Level:     logger.INFO,
		Component: "monitor",
		Console:   true,
		LogFile:   "", // Can be configured later
	}
	
	monitorLogger, err := logger.NewLogger(logConfig)
	if err != nil {
		// Fallback to basic logging if logger creation fails
		fmt.Printf("Failed to create monitor logger: %v\n", err)
		monitorLogger = nil
	}
	
	// Initialize error handling
	errorHandler := errors.NewErrorHandler()
	recoveryManager := errors.NewRecoveryManager()
	
	cm := &ConnectionMonitor{
		connections:        make(map[string]*Connection),
		newConnCallback:    callback,
		lastCleanup:        time.Now(),
		connectionCount:    0,
		maxConnections:     10000,
		logger:             monitorLogger,
		errorHandler:       errorHandler,
		recoveryManager:    recoveryManager,
		consecutiveErrors:  0,
		maxConsecutiveErrs: 5,
	}
	
	// Setup error handlers
	cm.setupErrorHandlers()
	
	// Start error handler
	errorHandler.Start()
	
	if monitorLogger != nil {
		monitorLogger.Info("Connection monitor initialized")
	}
	
	return cm
}

// setupErrorHandlers configures error handling for different error types
func (cm *ConnectionMonitor) setupErrorHandlers() {
	if cm.errorHandler == nil {
		return
	}
	
	// Network error handler
	cm.errorHandler.RegisterHandler(errors.ErrorTypeNetwork, func(err *errors.CLISnitchError) {
		if cm.logger != nil {
			cm.logger.ErrorWithDetails(err, "Network error in monitor", err.Context)
		}
		
		// Attempt recovery for network errors
		if err.Recoverable {
			if recoveryErr := cm.recoveryManager.AttemptRecovery(err); recoveryErr == nil {
				if cm.logger != nil {
					cm.logger.Info("Successfully recovered from network error")
				}
				cm.consecutiveErrors = 0
			}
		}
	})
	
	// Monitor error handler
	cm.errorHandler.RegisterHandler(errors.ErrorTypeMonitor, func(err *errors.CLISnitchError) {
		if cm.logger != nil {
			cm.logger.ErrorWithDetails(err, "Monitor subsystem error", err.Context)
		}
		
		cm.consecutiveErrors++
		if cm.consecutiveErrors >= cm.maxConsecutiveErrs {
			if cm.logger != nil {
				cm.logger.Error("Too many consecutive monitor errors, escalating")
			}
		}
	})
	
	// System error handler
	cm.errorHandler.RegisterHandler(errors.ErrorTypeSystem, func(err *errors.CLISnitchError) {
		if cm.logger != nil {
			cm.logger.ErrorWithDetails(err, "System error in monitor", err.Context)
		}
	})
}

// Close gracefully shuts down the monitor with proper cleanup
func (cm *ConnectionMonitor) Close() error {
	if cm.logger != nil {
		cm.logger.Info("Shutting down connection monitor")
	}
	
	if cm.errorHandler != nil {
		cm.errorHandler.Close()
	}
	
	if cm.logger != nil {
		cm.logger.Info("Connection monitor shutdown complete")
		return cm.logger.Close()
	}
	
	return nil
}

// parseConnectionLine parses a single lsof output line into a Connection struct
func parseConnectionLine(line string) (*Connection, error) {
	// Skip header line
	if strings.HasPrefix(line, "COMMAND") {
		return nil, nil
	}

	// Split by whitespace, but be careful with IPv6 addresses
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return nil, fmt.Errorf("insufficient fields in line: %s", line)
	}

	// Parse PID
	pid, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("invalid PID: %s", fields[1])
	}

	conn := &Connection{
		PID:         pid,
		ProcessName: fields[0],
		User:        fields[2],
		Timestamp:   time.Now(),
	}

	// Find the connection info - look for TCP or UDP and the connection string
	var connectionInfo string
	for i, field := range fields {
		if strings.Contains(field, "TCP") || strings.Contains(field, "UDP") {
			conn.Protocol = strings.ToLower(field)
			if i+1 < len(fields) {
				connectionInfo = fields[i+1]
			}
			break
		}
	}

	if connectionInfo == "" {
		return nil, fmt.Errorf("no connection info found in line: %s", line)
	}

	// Parse connection string (e.g., "10.10.10.111:53880->10.10.20.249:49154")
	if err := parseConnectionInfo(conn, connectionInfo); err != nil {
		return nil, fmt.Errorf("failed to parse connection info: %v", err)
	}

	// Extract state from the end of the line
	if strings.Contains(line, "(ESTABLISHED)") {
		conn.State = "ESTABLISHED"
	} else if strings.Contains(line, "(LISTEN)") {
		conn.State = "LISTEN"
	} else {
		conn.State = "UNKNOWN"
	}

	return conn, nil
}

// parseConnectionInfo parses the connection address information
func parseConnectionInfo(conn *Connection, info string) error {
	// Handle different formats:
	// IPv4: "10.10.10.111:53880->10.10.20.249:49154"
	// IPv6: "[fe80:15::d45a:1149:cd24:a1f8]:1024->[fe80:15::f7f4:5e86:c4cb:cdfa]:1024"
	// Listening: "*:53876"

	if strings.Contains(info, "->") {
		// Outbound connection
		parts := strings.Split(info, "->")
		if len(parts) != 2 {
			return fmt.Errorf("invalid connection format: %s", info)
		}

		if err := parseAddress(parts[0], &conn.LocalAddr, &conn.LocalPort); err != nil {
			return fmt.Errorf("failed to parse local address: %v", err)
		}

		if err := parseAddress(parts[1], &conn.RemoteAddr, &conn.RemotePort); err != nil {
			return fmt.Errorf("failed to parse remote address: %v", err)
		}
	} else {
		// Listening connection
		if err := parseAddress(info, &conn.LocalAddr, &conn.LocalPort); err != nil {
			return fmt.Errorf("failed to parse listening address: %v", err)
		}
	}

	return nil
}

// parseAddress parses an address:port combination (handles both IPv4 and IPv6)
func parseAddress(addr string, ip *string, port *string) error {
	if addr == "*:*" {
		*ip = "*"
		*port = "*"
		return nil
	}

	// IPv6 format: [address]:port
	if strings.HasPrefix(addr, "[") {
		re := regexp.MustCompile(`^\[([^\]]+)\]:(.+)$`)
		matches := re.FindStringSubmatch(addr)
		if len(matches) != 3 {
			return fmt.Errorf("invalid IPv6 format: %s", addr)
		}
		*ip = matches[1]
		*port = matches[2]
		return nil
	}

	// IPv4 format: address:port
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return fmt.Errorf("no port separator found: %s", addr)
	}

	*ip = addr[:lastColon]
	*port = addr[lastColon+1:]
	return nil
}

// GetCurrentConnections retrieves current network connections using lsof
func (cm *ConnectionMonitor) GetCurrentConnections() ([]*Connection, error) {
	startTime := time.Now()
	
	if cm.logger != nil {
		cm.logger.Debug("Starting lsof command to retrieve network connections")
	}
	
	// Run lsof to get network connections
	cmd := exec.Command("lsof", "-i", "tcp", "-n")
	output, err := cmd.Output()
	
	processingTime := time.Since(startTime)
	
	if err != nil {
		// Create detailed error with context
		cliError := errors.NewError(errors.ErrorTypeNetwork, errors.SeverityMedium, "Failed to execute lsof command").
			WithCause(err).
			WithComponent("monitor").
			WithContext("command", "lsof -i tcp -n").
			WithContext("processing_time", processingTime).
			WithRecovery("Check if lsof is installed and accessible").
			Build()
		
		if cm.errorHandler != nil {
			cm.errorHandler.Submit(cliError)
		}
		
		return nil, fmt.Errorf("lsof command failed: %v", err)
	}
	
	if cm.logger != nil {
		cm.logger.Debug("lsof command completed successfully in %v", processingTime)
	}
	
	var connections []*Connection
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineCount := 0
	parseErrors := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++
		
		conn, err := cm.parseConnectionLineWithErrorHandling(line, lineCount)
		if err != nil {
			parseErrors++
			if cm.logger != nil {
				cm.logger.Debug("Failed to parse line %d: %v | Line: %s", lineCount, err, line)
			}
			continue
		}
		if conn != nil {
			connections = append(connections, conn)
		}
	}

	if err := scanner.Err(); err != nil {
		cliError := errors.NewError(errors.ErrorTypeSystem, errors.SeverityMedium, "Error reading lsof output").
			WithCause(err).
			WithComponent("monitor").
			WithContext("lines_processed", lineCount).
			WithContext("parse_errors", parseErrors).
			Build()
		
		if cm.errorHandler != nil {
			cm.errorHandler.Submit(cliError)
		}
		
		return nil, fmt.Errorf("error reading lsof output: %v", err)
	}
	
	// Log processing statistics
	if cm.logger != nil {
		cm.logger.InfoWithMetrics("Connection scan completed", map[string]interface{}{
			"total_lines":      lineCount,
			"connections_found": len(connections),
			"parse_errors":     parseErrors,
			"processing_time":  processingTime,
			"error_rate":       float64(parseErrors) / float64(lineCount),
		})
	}
	
	// Warn if error rate is high
	if lineCount > 0 && float64(parseErrors)/float64(lineCount) > 0.1 {
		if cm.logger != nil {
			cm.logger.WarnWithRecovery(
				fmt.Sprintf("High parse error rate: %d/%d (%.1f%%)", parseErrors, lineCount, float64(parseErrors)/float64(lineCount)*100),
				"Check lsof output format compatibility",
			)
		}
	}

	return connections, nil
}

// parseConnectionLineWithErrorHandling parses a connection line with error context
func (cm *ConnectionMonitor) parseConnectionLineWithErrorHandling(line string, lineNumber int) (*Connection, error) {
	conn, err := parseConnectionLine(line)
	if err != nil {
		// Create detailed parsing error
		cliError := errors.NewParsingError(
			fmt.Sprintf("Failed to parse lsof output line %d", lineNumber),
			line,
			err,
		)
		cliError.Component = "monitor"
		if cliError.Context == nil {
			cliError.Context = make(map[string]interface{})
		}
		cliError.Context["line_number"] = lineNumber
		
		if cm.errorHandler != nil {
			cm.errorHandler.Submit(cliError)
		}
		
		return nil, err
	}
	return conn, nil
}

// StartMonitoring begins continuous monitoring with error handling and recovery
func (cm *ConnectionMonitor) StartMonitoring(ctx context.Context, interval time.Duration) error {
	if cm.logger != nil {
		cm.logger.Info("Starting network monitoring with %v interval", interval)
	}
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	// Performance monitoring variables
	var consecutiveErrors int
	const baseInterval = 2 * time.Second
	const maxInterval = 30 * time.Second
	
	// Statistics tracking
	stats := struct {
		totalScans       int
		totalConnections int
		totalErrors      int
		startTime        time.Time
	}{
		startTime: time.Now(),
	}

	for {
		select {
		case <-ctx.Done():
			if cm.logger != nil {
				uptime := time.Since(stats.startTime)
				cm.logger.InfoWithMetrics("Monitoring stopped gracefully", map[string]interface{}{
					"uptime":            uptime,
					"total_scans":       stats.totalScans,
					"total_connections": stats.totalConnections,
					"total_errors":      stats.totalErrors,
					"avg_connections":   float64(stats.totalConnections) / float64(stats.totalScans),
				})
			}
			return ctx.Err()
			
		case <-ticker.C:
			stats.totalScans++
			scanStartTime := time.Now()
			
			connections, err := cm.GetCurrentConnections()
			scanDuration := time.Since(scanStartTime)
			
			if err != nil {
				consecutiveErrors++
				stats.totalErrors++
				
				if cm.logger != nil {
					cm.logger.ErrorWithDetails(err, "Monitor scan failed", map[string]interface{}{
						"consecutive_errors": consecutiveErrors,
						"scan_duration":     scanDuration,
						"scan_number":       stats.totalScans,
					})
				}
				
				// Create monitor error for error handling system
				monitorError := errors.NewMonitorError(
					fmt.Sprintf("Monitoring scan #%d failed", stats.totalScans),
					err,
				)
				monitorError.Component = "monitor"
				if monitorError.Context == nil {
					monitorError.Context = make(map[string]interface{})
				}
				monitorError.Context["consecutive_errors"] = consecutiveErrors
				monitorError.Context["scan_duration"] = scanDuration
				
				if consecutiveErrors >= cm.maxConsecutiveErrs {
					monitorError.Severity = errors.SeverityCritical
					if cm.errorHandler != nil {
						cm.errorHandler.Submit(monitorError)
					}
					return fmt.Errorf("too many consecutive monitoring errors (%d): %v", consecutiveErrors, err)
				}
				
				if cm.errorHandler != nil {
					cm.errorHandler.Submit(monitorError)
				}
				
				// Adaptive backoff on errors
				if consecutiveErrors > 2 {
					newInterval := time.Duration(float64(interval) * 1.5)
					if newInterval > maxInterval {
						newInterval = maxInterval
					}
					ticker.Reset(newInterval)
					if cm.logger != nil {
						cm.logger.WarnWithRecovery(
							fmt.Sprintf("Adjusted monitoring interval to %v due to errors", newInterval),
							"Fix underlying network issues to restore normal interval",
						)
					}
				}
				continue
			}
			
			// Reset error counter on success
			if consecutiveErrors > 0 {
				if cm.logger != nil {
					cm.logger.Info("Monitoring recovered after %d consecutive errors", consecutiveErrors)
				}
				consecutiveErrors = 0
				ticker.Reset(baseInterval) // Reset to normal interval
			}

			// Process new connections with error handling
			newConnectionsFound := 0
			for _, conn := range connections {
				if cm.processNewConnection(conn) {
					newConnectionsFound++
					stats.totalConnections++
				}
			}
			
			// Cleanup with error handling
			if err := cm.performAdaptiveCleanup(); err != nil {
				if cm.logger != nil {
					cm.logger.WarnWithRecovery(
						fmt.Sprintf("Cleanup operation failed: %v", err),
						"Monitor will continue but memory usage may increase",
					)
				}
			}
			
			// Performance logging for significant events
			if newConnectionsFound > 0 || scanDuration > 500*time.Millisecond {
				if cm.logger != nil {
					cm.logger.InfoWithMetrics("Monitoring scan completed", map[string]interface{}{
						"new_connections":    newConnectionsFound,
						"total_tracked":     len(cm.connections),
						"scan_duration":     scanDuration,
						"scan_number":       stats.totalScans,
						"connections_per_sec": float64(newConnectionsFound) / scanDuration.Seconds(),
					})
				}
			}
		}
	}
}

// processNewConnection handles new connection detection with error handling
func (cm *ConnectionMonitor) processNewConnection(conn *Connection) bool {
	connKey := cm.getConnectionKey(conn)
	
	if _, exists := cm.connections[connKey]; !exists && cm.isOutboundConnection(conn) {
		// New outbound connection detected
		cm.connections[connKey] = conn
		cm.connectionCount++
		
		// Prevent memory exhaustion with error reporting
		if cm.connectionCount > cm.maxConnections {
			if cm.logger != nil {
				cm.logger.WarnWithRecovery(
					fmt.Sprintf("Connection limit reached (%d), forcing cleanup", cm.maxConnections),
					"Consider increasing maxConnections or reducing cleanup interval",
				)
			}
			
			if err := cm.forceCleanupOldConnections(); err != nil {
				if cm.logger != nil {
					cm.logger.Error("Force cleanup failed: %v", err)
				}
			}
		}
		
		// Call callback with error handling
		if cm.newConnCallback != nil {
			defer func() {
				if r := recover(); r != nil {
					if cm.logger != nil {
						cm.logger.Error("Connection callback panicked: %v", r)
					}
				}
			}()
			
			cm.newConnCallback(conn)
		}
		
		return true // New connection processed
	}
	return false // Not a new connection
}

// performAdaptiveCleanup performs cleanup with error handling
func (cm *ConnectionMonitor) performAdaptiveCleanup() error {
	defer func() {
		if r := recover(); r != nil {
			if cm.logger != nil {
				cm.logger.Error("Cleanup operation panicked: %v", r)
			}
		}
	}()
	
	cm.adaptiveCleanup()
	return nil
}

// cleanupOldConnections removes connections that are older than 5 minutes
func (cm *ConnectionMonitor) cleanupOldConnections() error {
	startTime := time.Now()
	cutoff := time.Now().Add(-5 * time.Minute)
	cleaned := 0
	
	if cm.logger != nil {
		cm.logger.Debug("Starting cleanup of connections older than 5 minutes")
	}
	
	defer func() {
		if r := recover(); r != nil {
			if cm.logger != nil {
				cm.logger.Error("Cleanup operation panicked: %v", r)
			}
		}
	}()
	
	for key, conn := range cm.connections {
		if conn.Timestamp.Before(cutoff) {
			delete(cm.connections, key)
			cm.connectionCount--
			cleaned++
		}
	}
	
	cm.lastCleanup = time.Now()
	cleanupDuration := time.Since(startTime)
	
	if cleaned > 0 {
		if cm.logger != nil {
			cm.logger.InfoWithMetrics("Connection cleanup completed", map[string]interface{}{
				"cleaned_connections": cleaned,
				"remaining_connections": len(cm.connections),
				"cleanup_duration": cleanupDuration,
				"cutoff_age": "5m",
			})
		}
	} else {
		if cm.logger != nil {
			cm.logger.Debug("No connections required cleanup (duration: %v)", cleanupDuration)
		}
	}
	
	return nil
}

// getConnectionKey creates a unique key for a connection
func (cm *ConnectionMonitor) getConnectionKey(conn *Connection) string {
	return fmt.Sprintf("%d:%s:%s:%s:%s", conn.PID, conn.RemoteAddr, conn.RemotePort, conn.LocalPort, conn.Protocol)
}

// isOutboundConnection determines if a connection is outbound (not listening)
func (cm *ConnectionMonitor) isOutboundConnection(conn *Connection) bool {
	return conn.State == "ESTABLISHED" && conn.RemoteAddr != "" && conn.RemoteAddr != "*"
}

// forceCleanupOldConnections forces a cleanup when memory limits are reached
func (cm *ConnectionMonitor) forceCleanupOldConnections() error {
	startTime := time.Now()
	
	if cm.logger != nil {
		cm.logger.Warn("Starting force cleanup due to memory limits")
	}
	
	defer func() {
		if r := recover(); r != nil {
			if cm.logger != nil {
				cm.logger.Error("Force cleanup panicked: %v", r)
			}
		}
	}()
	
	// More aggressive cleanup - remove connections older than 2 minutes
	cutoff := time.Now().Add(-2 * time.Minute)
	cleaned := 0
	
	for key, conn := range cm.connections {
		if conn.Timestamp.Before(cutoff) {
			delete(cm.connections, key)
			cm.connectionCount--
			cleaned++
		}
	}
	
	// If still too many, remove oldest 20%
	if cm.connectionCount > cm.maxConnections {
		if cm.logger != nil {
			cm.logger.Warn("Still over limit after aggressive cleanup, removing oldest 20%")
		}
		
		connectionsToRemove := make([]*Connection, 0, len(cm.connections))
		for _, conn := range cm.connections {
			connectionsToRemove = append(connectionsToRemove, conn)
		}
		
		// Remove oldest 20%
		removeCount := len(connectionsToRemove) / 5
		for i := 0; i < removeCount && len(cm.connections) > 0; i++ {
			// Find and remove oldest connection
			oldestKey := ""
			var oldestTime time.Time
			
			for key, conn := range cm.connections {
				if oldestKey == "" || conn.Timestamp.Before(oldestTime) {
					oldestKey = key
					oldestTime = conn.Timestamp
				}
			}
			
			if oldestKey != "" {
				delete(cm.connections, oldestKey)
				cm.connectionCount--
				cleaned++
			}
		}
	}
	
	cm.lastCleanup = time.Now()
	cleanupDuration := time.Since(startTime)
	
	if cm.logger != nil {
		cm.logger.InfoWithMetrics("Force cleanup completed", map[string]interface{}{
			"cleaned_connections": cleaned,
			"remaining_connections": len(cm.connections),
			"cleanup_duration": cleanupDuration,
			"still_over_limit": cm.connectionCount > cm.maxConnections,
		})
	}
	
	// Check if we're still over the limit
	if cm.connectionCount > cm.maxConnections {
		err := fmt.Errorf("force cleanup failed to reduce connections below limit: %d > %d", 
			cm.connectionCount, cm.maxConnections)
		
		if cm.logger != nil {
			cm.logger.Error("Force cleanup insufficient: %v", err)
		}
		
		// Create system error for critical memory condition
		cliError := errors.NewError(errors.ErrorTypeSystem, errors.SeverityCritical, 
			"Memory management failure: unable to reduce connection count").
			WithCause(err).
			WithComponent("monitor").
			WithContext("current_count", cm.connectionCount).
			WithContext("max_allowed", cm.maxConnections).
			WithContext("cleaned_count", cleaned).
			WithRecovery("Restart monitoring service or increase memory limits").
			Build()
		
		if cm.errorHandler != nil {
			cm.errorHandler.Submit(cliError)
		}
		
		return err
	}
	
	return nil
}

// adaptiveCleanup adjusts cleanup frequency based on connection count and time with error handling
func (cm *ConnectionMonitor) adaptiveCleanup() error {
	defer func() {
		if r := recover(); r != nil {
			if cm.logger != nil {
				cm.logger.Error("Adaptive cleanup panicked: %v", r)
			}
		}
	}()
	
	timeSinceLastCleanup := time.Since(cm.lastCleanup)
	
	// Adaptive cleanup frequency based on connection count
	var cleanupInterval time.Duration
	switch {
	case cm.connectionCount > 5000:
		cleanupInterval = 30 * time.Second  // High activity
	case cm.connectionCount > 1000:
		cleanupInterval = 2 * time.Minute   // Medium activity  
	default:
		cleanupInterval = 5 * time.Minute   // Low activity
	}
	
	if cm.logger != nil {
		cm.logger.Debug("Adaptive cleanup check: %d connections, %v since last cleanup, %v interval", 
			cm.connectionCount, timeSinceLastCleanup, cleanupInterval)
	}
	
	if timeSinceLastCleanup >= cleanupInterval {
		if cm.logger != nil {
			cm.logger.Debug("Triggering adaptive cleanup (interval: %v)", cleanupInterval)
		}
		return cm.cleanupOldConnections()
	}
	
	return nil
} 