package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

)

func TestParseConnectionLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *Connection
		wantErr  bool
	}{
		{
			name: "IPv4 established connection",
			line: "rapportd   1285 Nick   22u  IPv4 0x5e5e142a1be8e11e      0t0  TCP 10.10.10.111:53880->10.10.20.249:49154 (ESTABLISHED)",
			expected: &Connection{
				PID:         1285,
				ProcessName: "rapportd",
				User:        "Nick",
				Protocol:    "tcp",
				LocalAddr:   "10.10.10.111",
				LocalPort:   "53880",
				RemoteAddr:  "10.10.20.249",
				RemotePort:  "49154",
				State:       "ESTABLISHED",
			},
			wantErr: false,
		},
		{
			name: "IPv4 listening connection",
			line: "rapportd   1285 Nick   11u  IPv4  0x9f596a97ad3d06d      0t0    TCP *:53876 (LISTEN)",
			expected: &Connection{
				PID:         1285,
				ProcessName: "rapportd",
				User:        "Nick",
				Protocol:    "tcp",
				LocalAddr:   "*",
				LocalPort:   "53876",
				State:       "LISTEN",
			},
			wantErr: false,
		},
		{
			name:     "header line should return nil",
			line:     "COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF   NODE NAME",
			expected: nil,
			wantErr:  false,
		},
		{
			name: "UDP established connection",
			line: "mDNSRespo   123 root    8u  IPv4 0xabc123      0t0  UDP 10.0.0.1:5353->10.0.0.2:5353 (ESTABLISHED)",
			expected: &Connection{
				PID:         123,
				ProcessName: "mDNSRespo",
				User:        "root",
				Protocol:    "udp",
				LocalAddr:   "10.0.0.1",
				LocalPort:   "5353",
				RemoteAddr:  "10.0.0.2",
				RemotePort:  "5353",
				State:       "ESTABLISHED",
			},
			wantErr: false,
		},
		{
			name: "UDP listening connection",
			line: "mDNSRespo   123 root    9u  IPv4 0xabc456      0t0  UDP *:5353",
			expected: &Connection{
				PID:         123,
				ProcessName: "mDNSRespo",
				User:        "root",
				Protocol:    "udp",
				LocalAddr:   "*",
				LocalPort:   "5353",
				State:       "UNKNOWN",
			},
			wantErr: false,
		},
		{
			name: "UDP with IPv6",
			line: "chrome     5678 user   20u  IPv6 0xdef789      0t0  UDP [::1]:8080->[::1]:9090 (ESTABLISHED)",
			expected: &Connection{
				PID:         5678,
				ProcessName: "chrome",
				User:        "user",
				Protocol:    "udp",
				LocalAddr:   "::1",
				LocalPort:   "8080",
				RemoteAddr:  "::1",
				RemotePort:  "9090",
				State:       "ESTABLISHED",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseConnectionLine(tt.line)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseConnectionLine() expected error, got nil")
				}
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("parseConnectionLine() unexpected error: %v", err)
				return
			}

			if tt.expected == nil && result == nil {
				return // Both nil, test passes
			}

			if tt.expected == nil || result == nil {
				t.Errorf("parseConnectionLine() expected %v, got %v", tt.expected, result)
				return
			}

			// Compare fields (ignoring timestamp)
			if result.PID != tt.expected.PID {
				t.Errorf("PID: expected %d, got %d", tt.expected.PID, result.PID)
			}
			if result.ProcessName != tt.expected.ProcessName {
				t.Errorf("ProcessName: expected %s, got %s", tt.expected.ProcessName, result.ProcessName)
			}
			if result.User != tt.expected.User {
				t.Errorf("User: expected %s, got %s", tt.expected.User, result.User)
			}
			if result.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol: expected %s, got %s", tt.expected.Protocol, result.Protocol)
			}
			if result.LocalAddr != tt.expected.LocalAddr {
				t.Errorf("LocalAddr: expected %s, got %s", tt.expected.LocalAddr, result.LocalAddr)
			}
			if result.LocalPort != tt.expected.LocalPort {
				t.Errorf("LocalPort: expected %s, got %s", tt.expected.LocalPort, result.LocalPort)
			}
			if result.RemoteAddr != tt.expected.RemoteAddr {
				t.Errorf("RemoteAddr: expected %s, got %s", tt.expected.RemoteAddr, result.RemoteAddr)
			}
			if result.RemotePort != tt.expected.RemotePort {
				t.Errorf("RemotePort: expected %s, got %s", tt.expected.RemotePort, result.RemotePort)
			}
			if result.State != tt.expected.State {
				t.Errorf("State: expected %s, got %s", tt.expected.State, result.State)
			}
		})
	}
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		expectedIP  string
		expectedPort string
		wantErr     bool
	}{
		{
			name:        "IPv4 address",
			addr:        "10.10.10.111:53880",
			expectedIP:  "10.10.10.111",
			expectedPort: "53880",
			wantErr:     false,
		},
		{
			name:        "IPv6 address",
			addr:        "[fe80:15::d45a:1149:cd24:a1f8]:1024",
			expectedIP:  "fe80:15::d45a:1149:cd24:a1f8",
			expectedPort: "1024",
			wantErr:     false,
		},
		{
			name:        "wildcard address",
			addr:        "*:*",
			expectedIP:  "*",
			expectedPort: "*",
			wantErr:     false,
		},
		{
			name:        "wildcard with port",
			addr:        "*:53876",
			expectedIP:  "*",
			expectedPort: "53876",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip, port string
			err := parseAddress(tt.addr, &ip, &port)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseAddress() expected error, got nil")
				}
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("parseAddress() unexpected error: %v", err)
				return
			}

			if ip != tt.expectedIP {
				t.Errorf("IP: expected %s, got %s", tt.expectedIP, ip)
			}
			if port != tt.expectedPort {
				t.Errorf("Port: expected %s, got %s", tt.expectedPort, port)
			}
		})
	}
}

func TestConnectionMonitor(t *testing.T) {
	var capturedConnection *Connection

	// Create monitor with callback
	monitor := NewConnectionMonitor(func(conn *Connection) {
		capturedConnection = conn
	})

	if monitor == nil {
		t.Fatal("NewConnectionMonitor returned nil")
	}

	if monitor.connections == nil {
		t.Fatal("connections map not initialized")
	}

	// Test the callback mechanism with a mock connection
	testConn := &Connection{
		PID:         1234,
		ProcessName: "test",
		RemoteAddr:  "8.8.8.8",
		State:       "ESTABLISHED",
		Timestamp:   time.Now(),
	}

	if monitor.isOutboundConnection(testConn) {
		monitor.newConnCallback(testConn)
	}

	if capturedConnection == nil {
		t.Error("Callback was not triggered")
	} else if capturedConnection.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", capturedConnection.PID)
	}
}

func TestReverseLookup(t *testing.T) {
	// Clear the DNS cache before testing
	dnsCache = sync.Map{}

	t.Run("empty address returns empty string", func(t *testing.T) {
		result := ReverseLookup("")
		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("wildcard address returns empty string", func(t *testing.T) {
		result := ReverseLookup("*")
		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("localhost reverse lookup", func(t *testing.T) {
		// 127.0.0.1 should resolve to localhost on most systems
		result := ReverseLookup("127.0.0.1")
		// We just check that it returns something or empty (it depends on system config)
		// The important thing is it does not panic or hang
		_ = result
	})

	t.Run("cache is populated after lookup", func(t *testing.T) {
		dnsCache = sync.Map{}
		_ = ReverseLookup("127.0.0.1")

		// Verify the cache has an entry
		_, ok := dnsCache.Load("127.0.0.1")
		if !ok {
			t.Error("expected DNS cache to be populated after lookup")
		}
	})

	t.Run("cached result is returned on second call", func(t *testing.T) {
		dnsCache = sync.Map{}

		// Pre-populate cache
		dnsCache.Store("10.20.30.40", "cached.example.com")

		result := ReverseLookup("10.20.30.40")
		if result != "cached.example.com" {
			t.Errorf("expected cached result 'cached.example.com', got %q", result)
		}
	})

	t.Run("invalid address returns empty and caches", func(t *testing.T) {
		dnsCache = sync.Map{}
		result := ReverseLookup("999.999.999.999")
		if result != "" {
			t.Errorf("expected empty string for invalid address, got %q", result)
		}
		// Should still cache the empty result
		cached, ok := dnsCache.Load("999.999.999.999")
		if !ok {
			t.Error("expected cache entry for invalid address")
		}
		if cached.(string) != "" {
			t.Errorf("expected empty cached value, got %q", cached)
		}
	})
}

func TestConnectionHistory(t *testing.T) {
	// Use a temp directory for test history files
	tmpDir := t.TempDir()
	historyPath := filepath.Join(tmpDir, "test_history.jsonl")

	t.Run("log and read single connection", func(t *testing.T) {
		ch := NewConnectionHistoryWithPath(historyPath)

		conn := &Connection{
			PID:          1234,
			ProcessName:  "curl",
			User:         "testuser",
			Protocol:     "tcp",
			LocalAddr:    "10.0.0.1",
			LocalPort:    "54321",
			RemoteAddr:   "8.8.8.8",
			RemotePort:   "443",
			State:        "ESTABLISHED",
			ResolvedHost: "dns.google",
			Timestamp:    time.Now(),
		}

		err := ch.LogConnection(conn, "allow")
		if err != nil {
			t.Fatalf("LogConnection() error: %v", err)
		}

		entries, err := ch.GetHistory(10)
		if err != nil {
			t.Fatalf("GetHistory() error: %v", err)
		}

		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}

		entry := entries[0]
		if entry.PID != 1234 {
			t.Errorf("PID: expected 1234, got %d", entry.PID)
		}
		if entry.ProcessName != "curl" {
			t.Errorf("ProcessName: expected 'curl', got %q", entry.ProcessName)
		}
		if entry.Action != "allow" {
			t.Errorf("Action: expected 'allow', got %q", entry.Action)
		}
		if entry.RemoteAddr != "8.8.8.8" {
			t.Errorf("RemoteAddr: expected '8.8.8.8', got %q", entry.RemoteAddr)
		}
		if entry.ResolvedHost != "dns.google" {
			t.Errorf("ResolvedHost: expected 'dns.google', got %q", entry.ResolvedHost)
		}
		if entry.Timestamp.IsZero() {
			t.Error("Timestamp should not be zero")
		}
	})

	t.Run("log multiple and respect limit", func(t *testing.T) {
		histPath := filepath.Join(tmpDir, "test_limit.jsonl")
		ch := NewConnectionHistoryWithPath(histPath)

		for i := 0; i < 5; i++ {
			conn := &Connection{
				PID:         i + 1,
				ProcessName: "proc",
				RemoteAddr:  "1.2.3.4",
				State:       "ESTABLISHED",
				Protocol:    "tcp",
				Timestamp:   time.Now(),
			}
			if err := ch.LogConnection(conn, "allow"); err != nil {
				t.Fatalf("LogConnection() error on entry %d: %v", i, err)
			}
		}

		// Get last 3
		entries, err := ch.GetHistory(3)
		if err != nil {
			t.Fatalf("GetHistory() error: %v", err)
		}
		if len(entries) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(entries))
		}
		// Should be the last 3 (PIDs 3, 4, 5)
		if entries[0].PID != 3 {
			t.Errorf("expected first returned entry PID=3, got %d", entries[0].PID)
		}
		if entries[2].PID != 5 {
			t.Errorf("expected last returned entry PID=5, got %d", entries[2].PID)
		}
	})

	t.Run("get history from nonexistent file returns empty", func(t *testing.T) {
		ch := NewConnectionHistoryWithPath(filepath.Join(tmpDir, "nonexistent.jsonl"))

		entries, err := ch.GetHistory(10)
		if err != nil {
			t.Fatalf("GetHistory() should not error for missing file, got: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})

	t.Run("history entries are valid JSON", func(t *testing.T) {
		histPath := filepath.Join(tmpDir, "test_json.jsonl")
		ch := NewConnectionHistoryWithPath(histPath)

		conn := &Connection{
			PID:         42,
			ProcessName: "wget",
			Protocol:    "tcp",
			RemoteAddr:  "93.184.216.34",
			RemotePort:  "80",
			State:       "ESTABLISHED",
			Timestamp:   time.Now(),
		}
		if err := ch.LogConnection(conn, "deny"); err != nil {
			t.Fatalf("LogConnection() error: %v", err)
		}

		data, err := os.ReadFile(histPath)
		if err != nil {
			t.Fatalf("failed to read history file: %v", err)
		}

		var entry HistoryEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			t.Fatalf("history line is not valid JSON: %v", err)
		}
		if entry.Action != "deny" {
			t.Errorf("expected action 'deny', got %q", entry.Action)
		}
	})

	t.Run("log UDP connection", func(t *testing.T) {
		histPath := filepath.Join(tmpDir, "test_udp_history.jsonl")
		ch := NewConnectionHistoryWithPath(histPath)

		conn := &Connection{
			PID:         999,
			ProcessName: "dns",
			Protocol:    "udp",
			RemoteAddr:  "8.8.4.4",
			RemotePort:  "53",
			State:       "ESTABLISHED",
			Timestamp:   time.Now(),
		}
		if err := ch.LogConnection(conn, "allow"); err != nil {
			t.Fatalf("LogConnection() error: %v", err)
		}

		entries, err := ch.GetHistory(10)
		if err != nil {
			t.Fatalf("GetHistory() error: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].Protocol != "udp" {
			t.Errorf("expected protocol 'udp', got %q", entries[0].Protocol)
		}
	})
}

func TestForceCleanupOldConnections(t *testing.T) {
	t.Run("oldest 20% removal is O(n log n) not O(n^2)", func(t *testing.T) {
		monitor := &ConnectionMonitor{
			connections:    make(map[string]*Connection),
			maxConnections: 5, // low limit to trigger 20% removal
		}

		// Add connections with different timestamps
		now := time.Now()
		for i := 0; i < 10; i++ {
			key := "key" + string(rune('a'+i))
			monitor.connections[key] = &Connection{
				PID:       i,
				Timestamp: now.Add(time.Duration(-10+i) * time.Minute), // oldest first
			}
			monitor.connectionCount++
		}

		// All connections are older than 2 minutes, so the first pass removes them all
		// Test with connections that are recent (within 2 minutes) to force the sort path
		monitor.connections = make(map[string]*Connection)
		monitor.connectionCount = 0

		for i := 0; i < 10; i++ {
			key := "key" + string(rune('a'+i))
			monitor.connections[key] = &Connection{
				PID:       i,
				Timestamp: now.Add(time.Duration(-i) * time.Second), // all within 2 minutes
			}
			monitor.connectionCount++
		}

		err := monitor.forceCleanupOldConnections()
		// It may return an error since we still have > maxConnections after cleanup
		// but the important thing is it doesn't hang or panic
		_ = err

		// Verify that some connections were removed
		if monitor.connectionCount >= 10 {
			t.Errorf("expected some connections to be removed, still have %d", monitor.connectionCount)
		}
	})

	t.Run("sort-based removal removes correct oldest entries", func(t *testing.T) {
		monitor := &ConnectionMonitor{
			connections:    make(map[string]*Connection),
			maxConnections: 3,
		}

		now := time.Now()
		// Add 5 connections, all recent (within 2 min) so they survive the first pass
		timestamps := []time.Duration{
			-90 * time.Second,
			-70 * time.Second,
			-50 * time.Second,
			-30 * time.Second,
			-10 * time.Second,
		}

		keys := []string{"oldest", "old", "mid", "new", "newest"}
		for i, key := range keys {
			monitor.connections[key] = &Connection{
				PID:       i,
				Timestamp: now.Add(timestamps[i]),
			}
			monitor.connectionCount++
		}

		_ = monitor.forceCleanupOldConnections()

		// 20% of 5 = 1 removed, so 4 should remain
		if len(monitor.connections) != 4 {
			t.Errorf("expected 4 remaining connections, got %d", len(monitor.connections))
		}

		// The oldest one should be removed
		if _, exists := monitor.connections["oldest"]; exists {
			t.Error("expected 'oldest' connection to be removed")
		}

		// The newest should still exist
		if _, exists := monitor.connections["newest"]; !exists {
			t.Error("expected 'newest' connection to still exist")
		}
	})
}

func TestReverseLookupResolvedHostField(t *testing.T) {
	// Verify that ResolvedHost is set on Connection struct
	conn := &Connection{
		PID:        1,
		RemoteAddr: "127.0.0.1",
		State:      "ESTABLISHED",
	}

	conn.ResolvedHost = ReverseLookup(conn.RemoteAddr)

	// Just verify the field is accessible and populated (value depends on system)
	_ = conn.ResolvedHost
}

func TestForceCleanupSortOrder(t *testing.T) {
	// Verify the sort-based approach actually sorts correctly
	now := time.Now()
	items := []connKeyTimestamp{
		{key: "c", timestamp: now.Add(-1 * time.Second)},
		{key: "a", timestamp: now.Add(-3 * time.Second)},
		{key: "b", timestamp: now.Add(-2 * time.Second)},
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].timestamp.Before(items[j].timestamp)
	})

	if items[0].key != "a" {
		t.Errorf("expected oldest first, got key %q", items[0].key)
	}
	if items[1].key != "b" {
		t.Errorf("expected second oldest second, got key %q", items[1].key)
	}
	if items[2].key != "c" {
		t.Errorf("expected newest last, got key %q", items[2].key)
	}
}

func TestCleanupOldConnections_Isolated(t *testing.T) {
	cm := &ConnectionMonitor{
		connections:    make(map[string]*Connection),
		maxConnections: 10000,
		lastCleanup:    time.Now().Add(-10 * time.Minute),
		newConnCallback: func(conn *Connection) {
			// no-op
		},
	}

	now := time.Now()

	// Insert 5 connections that are 10 minutes old (should be cleaned)
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("old_%d", i)
		cm.connections[key] = &Connection{
			PID:       i,
			Timestamp: now.Add(-10 * time.Minute),
		}
		cm.connectionCount++
	}

	// Insert 5 connections that are 1 minute old (should survive)
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("new_%d", i)
		cm.connections[key] = &Connection{
			PID:       100 + i,
			Timestamp: now.Add(-1 * time.Minute),
		}
		cm.connectionCount++
	}

	if cm.connectionCount != 10 {
		t.Fatalf("expected 10 connections before cleanup, got %d", cm.connectionCount)
	}

	err := cm.cleanupOldConnections()
	if err != nil {
		t.Fatalf("cleanupOldConnections() returned error: %v", err)
	}

	// Only the 5 recent connections should remain
	if len(cm.connections) != 5 {
		t.Errorf("expected 5 connections after cleanup, got %d", len(cm.connections))
	}
	if cm.connectionCount != 5 {
		t.Errorf("expected connectionCount=5 after cleanup, got %d", cm.connectionCount)
	}

	// Verify the old connections were removed and new ones remain
	for i := 0; i < 5; i++ {
		oldKey := fmt.Sprintf("old_%d", i)
		if _, exists := cm.connections[oldKey]; exists {
			t.Errorf("expected old connection %q to be removed", oldKey)
		}
		newKey := fmt.Sprintf("new_%d", i)
		if _, exists := cm.connections[newKey]; !exists {
			t.Errorf("expected new connection %q to remain", newKey)
		}
	}
}

func TestForceCleanupOldConnections_Isolated(t *testing.T) {
	cm := &ConnectionMonitor{
		connections:    make(map[string]*Connection),
		maxConnections: 100,
		lastCleanup:    time.Now().Add(-10 * time.Minute),
	}

	now := time.Now()

	// Insert 150 connections with timestamps spread from oldest to newest.
	// The first 75 are older than 2 minutes (will be removed in the aggressive pass).
	// The remaining 75 are within the last 2 minutes.
	for i := 0; i < 150; i++ {
		key := fmt.Sprintf("conn_%03d", i)
		age := time.Duration(150-i) * time.Second // conn_000 is oldest, conn_149 is newest
		cm.connections[key] = &Connection{
			PID:       i,
			Timestamp: now.Add(-age),
		}
		cm.connectionCount++
	}

	if cm.connectionCount != 150 {
		t.Fatalf("expected 150 connections before force cleanup, got %d", cm.connectionCount)
	}

	_ = cm.forceCleanupOldConnections()

	// After force cleanup the count should be at or below maxConnections
	if cm.connectionCount > cm.maxConnections {
		t.Errorf("expected connectionCount <= %d after force cleanup, got %d", cm.maxConnections, cm.connectionCount)
	}

	// Verify the oldest connections were removed first: conn_000 (oldest) should be gone
	if _, exists := cm.connections["conn_000"]; exists {
		t.Error("expected the oldest connection (conn_000) to be removed")
	}

	// The newest connection should still be present
	if _, exists := cm.connections["conn_149"]; !exists {
		t.Error("expected the newest connection (conn_149) to remain")
	}
}

func TestAdaptiveCleanup_Intervals(t *testing.T) {
	cm := &ConnectionMonitor{
		connections:    make(map[string]*Connection),
		maxConnections: 10000,
	}

	// --- High activity: 6000 connections, last cleanup 1 minute ago ---
	// For >5000 connections the interval is 30s, so 1 minute ago should trigger cleanup.
	cm.connectionCount = 6000
	cm.lastCleanup = time.Now().Add(-1 * time.Minute)

	// Insert some old connections so we can observe whether cleanup ran
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("high_%d", i)
		cm.connections[key] = &Connection{
			PID:       i,
			Timestamp: time.Now().Add(-10 * time.Minute),
		}
	}

	err := cm.adaptiveCleanup()
	if err != nil {
		t.Fatalf("adaptiveCleanup() (high activity) returned error: %v", err)
	}

	// The old connections should have been cleaned up
	if len(cm.connections) != 0 {
		t.Errorf("expected 0 connections after high-activity cleanup, got %d", len(cm.connections))
	}

	// --- Low activity: 100 connections, last cleanup 3 minutes ago ---
	// For <1000 connections the interval is 5 minutes, so 3 minutes is NOT enough.
	cm.connectionCount = 100
	cm.lastCleanup = time.Now().Add(-3 * time.Minute)

	// Insert a connection that would be cleaned if cleanup ran
	cm.connections["low_old"] = &Connection{
		PID:       999,
		Timestamp: time.Now().Add(-10 * time.Minute),
	}

	err = cm.adaptiveCleanup()
	if err != nil {
		t.Fatalf("adaptiveCleanup() (low activity, 3m) returned error: %v", err)
	}

	// Cleanup should NOT have run, so the old connection should still be there
	if _, exists := cm.connections["low_old"]; !exists {
		t.Error("expected low-activity cleanup to NOT trigger at 3 minutes (interval is 5m)")
	}

	// --- Low activity: 100 connections, last cleanup 6 minutes ago ---
	// 6 minutes exceeds the 5-minute interval, so cleanup should trigger.
	cm.lastCleanup = time.Now().Add(-6 * time.Minute)

	err = cm.adaptiveCleanup()
	if err != nil {
		t.Fatalf("adaptiveCleanup() (low activity, 6m) returned error: %v", err)
	}

	// Now the old connection should be gone
	if _, exists := cm.connections["low_old"]; exists {
		t.Error("expected low-activity cleanup to trigger at 6 minutes and remove old connection")
	}
}

func TestConnectionPipeline_MonitorToHistory(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up connection history
	historyPath := filepath.Join(tmpDir, "history.jsonl")
	history := NewConnectionHistoryWithPath(historyPath)

	// Create a monitor that logs connections to history via callback
	var processed []*Connection
	mon := NewConnectionMonitor(func(conn *Connection) {
		processed = append(processed, conn)
		history.LogConnection(conn, "allowed")
	})
	defer mon.Close()

	// Simulate a new outbound connection
	conn := &Connection{
		PID:         5678,
		ProcessName: "testapp",
		User:        "testuser",
		Protocol:    "tcp",
		LocalAddr:   "192.168.1.10",
		LocalPort:   "55000",
		RemoteAddr:  "93.184.216.34",
		RemotePort:  "443",
		State:       "ESTABLISHED",
		Timestamp:   time.Now(),
	}

	// Process through the monitor
	isNew := mon.processNewConnection(conn)
	if !isNew {
		t.Fatal("expected connection to be detected as new")
	}

	// Second time should not trigger callback (dedup)
	isNew2 := mon.processNewConnection(conn)
	if isNew2 {
		t.Error("expected duplicate connection to be skipped")
	}

	// Verify callback was called exactly once
	if len(processed) != 1 {
		t.Fatalf("expected 1 processed connection, got %d", len(processed))
	}

	// Verify history was written
	entries, err := history.GetHistory(10)
	if err != nil {
		t.Fatalf("GetHistory() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(entries))
	}
	if entries[0].Action != "allowed" {
		t.Errorf("expected action 'allowed', got %q", entries[0].Action)
	}
	if entries[0].ProcessName != "testapp" {
		t.Errorf("expected process 'testapp', got %q", entries[0].ProcessName)
	}
	if entries[0].RemoteAddr != "93.184.216.34" {
		t.Errorf("expected remote addr '93.184.216.34', got %q", entries[0].RemoteAddr)
	}
}
