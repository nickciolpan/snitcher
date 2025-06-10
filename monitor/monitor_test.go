package monitor

import (
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