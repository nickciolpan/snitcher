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
)

// Connection represents a network connection
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

// ConnectionMonitor handles network connection monitoring
type ConnectionMonitor struct {
	connections map[string]*Connection
	newConnCallback func(*Connection)
}

// NewConnectionMonitor creates a new connection monitor
func NewConnectionMonitor(callback func(*Connection)) *ConnectionMonitor {
	return &ConnectionMonitor{
		connections: make(map[string]*Connection),
		newConnCallback: callback,
	}
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
	// Run lsof to get network connections
	cmd := exec.Command("lsof", "-i", "tcp", "-n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run lsof: %v", err)
	}

	var connections []*Connection
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := scanner.Text()
		conn, err := parseConnectionLine(line)
		if err != nil {
			// Skip problematic lines but log them for debugging
			fmt.Printf("Warning: failed to parse line: %v\n", err)
			continue
		}
		if conn != nil {
			connections = append(connections, conn)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading lsof output: %v", err)
	}

	return connections, nil
}

// StartMonitoring begins continuous monitoring of network connections
func (cm *ConnectionMonitor) StartMonitoring(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			connections, err := cm.GetCurrentConnections()
			if err != nil {
				// Log error but don't stop monitoring
				fmt.Printf("Warning: Error getting connections: %v\n", err)
				continue
			}

			// Check for new connections
			for _, conn := range connections {
				connKey := cm.getConnectionKey(conn)
				if _, exists := cm.connections[connKey]; !exists && cm.isOutboundConnection(conn) {
					// New outbound connection detected
					cm.connections[connKey] = conn
					if cm.newConnCallback != nil {
						cm.newConnCallback(conn)
					}
				}
			}

			// Clean up old connections periodically (every 100 iterations)
			cm.cleanupOldConnections()
		}
	}
}

// cleanupOldConnections removes connections that are older than 5 minutes
func (cm *ConnectionMonitor) cleanupOldConnections() {
	cutoff := time.Now().Add(-5 * time.Minute)
	for key, conn := range cm.connections {
		if conn.Timestamp.Before(cutoff) {
			delete(cm.connections, key)
		}
	}
}

// getConnectionKey creates a unique key for a connection
func (cm *ConnectionMonitor) getConnectionKey(conn *Connection) string {
	return fmt.Sprintf("%d:%s:%s:%s:%s", conn.PID, conn.RemoteAddr, conn.RemotePort, conn.LocalPort, conn.Protocol)
}

// isOutboundConnection determines if a connection is outbound (not listening)
func (cm *ConnectionMonitor) isOutboundConnection(conn *Connection) bool {
	return conn.State == "ESTABLISHED" && conn.RemoteAddr != "" && conn.RemoteAddr != "*"
} 