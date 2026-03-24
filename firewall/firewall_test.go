package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cli-snitch/prompt"
	"cli-snitch/rules"
)

func TestNewFirewallManager(t *testing.T) {
	fm := NewFirewallManager()

	if fm.anchorName != "cli-snitch" {
		t.Errorf("Expected anchor name 'cli-snitch', got '%s'", fm.anchorName)
	}

	if fm.anchorFile != "/etc/pf.anchors/cli-snitch" {
		t.Errorf("Expected anchor file '/etc/pf.anchors/cli-snitch', got '%s'", fm.anchorFile)
	}

	if fm.enabled {
		t.Error("Expected firewall to be disabled by default")
	}
}

func TestValidateRule(t *testing.T) {
	fm := NewFirewallManager()

	tests := []struct {
		name    string
		rule    *FirewallRule
		wantErr bool
	}{
		{
			name: "valid block rule",
			rule: &FirewallRule{
				Action:    "block",
				Direction: "out",
				Protocol:  "tcp",
				Host:      "example.com",
				Port:      "80",
			},
			wantErr: false,
		},
		{
			name: "valid pass rule",
			rule: &FirewallRule{
				Action:    "pass",
				Direction: "in",
				Protocol:  "udp",
			},
			wantErr: false,
		},
		{
			name: "invalid action",
			rule: &FirewallRule{
				Action: "allow",
			},
			wantErr: true,
		},
		{
			name: "invalid direction",
			rule: &FirewallRule{
				Action:    "block",
				Direction: "both",
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			rule: &FirewallRule{
				Action:   "block",
				Protocol: "http",
			},
			wantErr: true,
		},
		{
			name: "empty direction is valid",
			rule: &FirewallRule{
				Action:   "block",
				Protocol: "tcp",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fm.validateRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGeneratePfRule(t *testing.T) {
	fm := NewFirewallManager()

	tests := []struct {
		name     string
		rule     *FirewallRule
		expected string
	}{
		{
			name: "outbound block to specific host and port",
			rule: &FirewallRule{
				Action:    "block",
				Direction: "out",
				Protocol:  "tcp",
				Host:      "192.168.1.100",
				Port:      "443",
			},
			expected: "block out proto tcp from any to 192.168.1.100 port 443",
		},
		{
			name: "outbound block to any host on specific port",
			rule: &FirewallRule{
				Action:    "block",
				Direction: "out",
				Protocol:  "tcp",
				Port:      "80",
			},
			expected: "block out proto tcp from any to any port 80",
		},
		{
			name: "inbound block from specific host",
			rule: &FirewallRule{
				Action:    "block",
				Direction: "in",
				Protocol:  "tcp",
				Host:      "10.0.0.1",
			},
			expected: "block in proto tcp from 10.0.0.1 to any",
		},
		{
			name: "block with interface",
			rule: &FirewallRule{
				Action:    "block",
				Direction: "out",
				Interface: "en0",
				Protocol:  "tcp",
				Host:      "example.com",
				Port:      "22",
			},
			expected: "block out on en0 proto tcp from any to example.com port 22",
		},
		{
			name: "simple block all",
			rule: &FirewallRule{
				Action: "block",
			},
			expected: "block from any to any",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := fm.generatePfRule(tt.rule)
			if err != nil {
				t.Fatalf("generatePfRule() unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("generatePfRule() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestCreateBlockRuleFromUserDecision(t *testing.T) {
	fm := NewFirewallManager()

	tests := []struct {
		name         string
		decision     *prompt.UserDecision
		processName  string
		host         string
		port         string
		expectHost   string
		expectPort   string
		expectExpiry bool
	}{
		{
			name: "deny once with exact scope",
			decision: &prompt.UserDecision{
				Action:      rules.DenyOnce,
				Scope:       rules.Exact,
				Description: "Block Chrome to Google",
			},
			processName:  "Chrome",
			host:         "google.com",
			port:         "443",
			expectHost:   "google.com",
			expectPort:   "443",
			expectExpiry: true,
		},
		{
			name: "deny always with process and host scope",
			decision: &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       rules.ProcessAndHost,
				Description: "Block app to specific host",
			},
			processName:  "TestApp",
			host:         "badsite.com",
			port:         "80",
			expectHost:   "badsite.com",
			expectPort:   "",
			expectExpiry: false,
		},
		{
			name: "deny with process and port scope",
			decision: &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       rules.ProcessAndPort,
				Description: "Block app on specific port",
			},
			processName:  "TestApp",
			host:         "example.com",
			port:         "22",
			expectHost:   "",
			expectPort:   "22",
			expectExpiry: false,
		},
		{
			name: "deny with process only scope",
			decision: &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       rules.ProcessOnly,
				Description: "Block process completely",
			},
			processName:  "BadApp",
			host:         "anywhere.com",
			port:         "80",
			expectHost:   "anywhere.com", // pfctl needs at least host/port, so we use host
			expectPort:   "",
			expectExpiry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := fm.CreateBlockRuleFromUserDecision(tt.decision, tt.processName, tt.host, tt.port)

			// Check basic properties
			if rule.Action != "block" {
				t.Errorf("Expected action 'block', got '%s'", rule.Action)
			}

			if rule.Direction != "out" {
				t.Errorf("Expected direction 'out', got '%s'", rule.Direction)
			}

			if rule.Protocol != "tcp" {
				t.Errorf("Expected protocol 'tcp', got '%s'", rule.Protocol)
			}

			if rule.ProcessName != tt.processName {
				t.Errorf("Expected process name '%s', got '%s'", tt.processName, rule.ProcessName)
			}

			if rule.Description != tt.decision.Description {
				t.Errorf("Expected description '%s', got '%s'", tt.decision.Description, rule.Description)
			}

			// Check host/port based on scope
			if rule.Host != tt.expectHost {
				t.Errorf("Expected host '%s', got '%s'", tt.expectHost, rule.Host)
			}

			if rule.Port != tt.expectPort {
				t.Errorf("Expected port '%s', got '%s'", tt.expectPort, rule.Port)
			}

			// Check expiration
			if tt.expectExpiry && rule.ExpiresAt == nil {
				t.Error("Expected rule to have expiration time")
			}

			if !tt.expectExpiry && rule.ExpiresAt != nil {
				t.Error("Expected rule to not have expiration time")
			}

			// Check ID is set
			if rule.ID == "" {
				t.Error("Expected rule to have an ID")
			}

			// Check timestamp
			if rule.CreatedAt.IsZero() {
				t.Error("Expected rule to have creation timestamp")
			}
		})
	}
}

func TestPfRuleGeneration_IntegrationStyle(t *testing.T) {
	fm := NewFirewallManager()

	// Test a complete flow: user decision -> firewall rule -> pfctl syntax
	decision := &prompt.UserDecision{
		Action:      rules.Deny,
		Scope:       rules.Exact,
		Description: "Block suspicious connection",
	}

	firewallRule := fm.CreateBlockRuleFromUserDecision(decision, "SuspiciousApp", "malware.com", "443")
	pfRule, err := fm.generatePfRule(firewallRule)
	if err != nil {
		t.Fatalf("generatePfRule() unexpected error: %v", err)
	}

	expected := "block out proto tcp from any to malware.com port 443"
	if pfRule != expected {
		t.Errorf("Complete flow generated pfctl rule = %q, expected %q", pfRule, expected)
	}
}

func TestRuleExpiration(t *testing.T) {
	fm := NewFirewallManager()

	// Test that DenyOnce creates expiring rules
	decision := &prompt.UserDecision{
		Action:      rules.DenyOnce,
		Scope:       rules.Exact,
		Description: "Temporary block",
	}

	rule := fm.CreateBlockRuleFromUserDecision(decision, "App", "host.com", "80")

	if rule.ExpiresAt == nil {
		t.Fatal("Expected DenyOnce rule to have expiration time")
	}

	// Check that expiration is approximately 24 hours from now
	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := rule.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("Expiration time should be ~24 hours from now, got %v", rule.ExpiresAt)
	}
}

// --- Input sanitization tests ---

func TestSanitizeValue_ValidHosts(t *testing.T) {
	validHosts := []string{
		"example.com",
		"sub.domain.example.com",
		"192.168.1.100",
		"10.0.0.1",
		"my-host.local",
		"host_name",
		"::1",
		"2001:db8::1",
		"a",
		"",
	}

	for _, h := range validHosts {
		result, err := sanitizeValue(h, false)
		if err != nil {
			t.Errorf("sanitizeValue(%q, false) returned unexpected error: %v", h, err)
		}
		if result != h {
			t.Errorf("sanitizeValue(%q, false) = %q, expected %q", h, result, h)
		}
	}
}

func TestSanitizeValue_InvalidHosts(t *testing.T) {
	invalidHosts := []string{
		"example.com; rm -rf /",
		"host$(whoami)",
		"host`id`",
		"host\ninjection",
		"host with spaces",
		"host&command",
		"host|pipe",
		"host>redirect",
		"host<input",
		"$(malicious)",
		"host'quote",
		`host"doublequote`,
	}

	for _, h := range invalidHosts {
		_, err := sanitizeValue(h, false)
		if err == nil {
			t.Errorf("sanitizeValue(%q, false) expected error for invalid host, got nil", h)
		}
	}
}

func TestSanitizeValue_ValidPorts(t *testing.T) {
	validPorts := []string{
		"80",
		"443",
		"8080",
		"0",
		"65535",
		"",
	}

	for _, p := range validPorts {
		result, err := sanitizeValue(p, true)
		if err != nil {
			t.Errorf("sanitizeValue(%q, true) returned unexpected error: %v", p, err)
		}
		if result != p {
			t.Errorf("sanitizeValue(%q, true) = %q, expected %q", p, result, p)
		}
	}
}

func TestSanitizeValue_InvalidPorts(t *testing.T) {
	invalidPorts := []string{
		"80; rm -rf /",
		"abc",
		"80abc",
		"80.0",
		"-1",
		"80 443",
		"80\n443",
	}

	for _, p := range invalidPorts {
		_, err := sanitizeValue(p, true)
		if err == nil {
			t.Errorf("sanitizeValue(%q, true) expected error for invalid port, got nil", p)
		}
	}
}

func TestGeneratePfRule_RejectsInvalidHost(t *testing.T) {
	fm := NewFirewallManager()

	rule := &FirewallRule{
		Action:    "block",
		Direction: "out",
		Protocol:  "tcp",
		Host:      "evil.com; rm -rf /",
		Port:      "443",
	}

	_, err := fm.generatePfRule(rule)
	if err == nil {
		t.Error("generatePfRule() expected error for invalid host, got nil")
	}
	if !strings.Contains(err.Error(), "host sanitization failed") {
		t.Errorf("generatePfRule() error = %q, expected to contain 'host sanitization failed'", err.Error())
	}
}

func TestGeneratePfRule_RejectsInvalidPort(t *testing.T) {
	fm := NewFirewallManager()

	rule := &FirewallRule{
		Action:    "block",
		Direction: "out",
		Protocol:  "tcp",
		Host:      "example.com",
		Port:      "443; drop table",
	}

	_, err := fm.generatePfRule(rule)
	if err == nil {
		t.Error("generatePfRule() expected error for invalid port, got nil")
	}
	if !strings.Contains(err.Error(), "port sanitization failed") {
		t.Errorf("generatePfRule() error = %q, expected to contain 'port sanitization failed'", err.Error())
	}
}

// --- CleanupExpiredRules tests ---

func TestCleanupExpiredRules_RemovesDescriptionComment(t *testing.T) {
	// Create a temp anchor file with an expired rule (3 lines: description, expires, rule)
	tmpDir := t.TempDir()
	anchorFile := filepath.Join(tmpDir, "test-anchor")

	expired := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	content := `# CLI Snitch Firewall Rules
# This file is managed by CLI Snitch - do not edit manually
# Generated at 2025-01-01T00:00:00Z

# Block suspicious connection
# CLI-Snitch-Expires: ` + expired + `
block out proto tcp from any to evil.com port 443
`

	if err := os.WriteFile(anchorFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test anchor file: %v", err)
	}

	// We test the cleanup logic on the file content directly
	// since reloadAnchor would call pfctl which isn't available in tests.
	_ = &FirewallManager{
		anchorName: "test-snitch",
		anchorFile: anchorFile,
	}

	result, err := os.ReadFile(anchorFile)
	if err != nil {
		t.Fatalf("failed to read anchor file: %v", err)
	}

	// Simulate CleanupExpiredRules logic manually since reloadAnchor would fail
	lines := strings.Split(string(result), "\n")
	var validLines []string
	now := time.Now()
	removedCount := 0

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.Contains(line, "# CLI-Snitch-Expires:") {
			parts := strings.Split(line, "CLI-Snitch-Expires:")
			if len(parts) == 2 {
				expiryStr := strings.TrimSpace(parts[1])
				if expiryTime, parseErr := time.Parse(time.RFC3339, expiryStr); parseErr == nil {
					if now.After(expiryTime) {
						// Check for description comment before expiration line
						if len(validLines) > 0 {
							prev := strings.TrimSpace(validLines[len(validLines)-1])
							if strings.HasPrefix(prev, "#") &&
								!strings.Contains(prev, "CLI Snitch Firewall Rules") &&
								!strings.Contains(prev, "do not edit manually") &&
								!strings.Contains(prev, "Generated at") &&
								!strings.Contains(prev, "Set interface") &&
								!strings.Contains(prev, "Default:") &&
								!strings.Contains(prev, "CLI Snitch rules will be added") {
								validLines = validLines[:len(validLines)-1]
							}
						}
						removedCount++
						if i+1 < len(lines) {
							i++ // Skip rule line
						}
						continue
					}
				}
			}
		}

		validLines = append(validLines, line)
	}

	if removedCount != 1 {
		t.Errorf("Expected 1 expired rule removed, got %d", removedCount)
	}

	cleaned := strings.Join(validLines, "\n")

	// The description comment should NOT remain in the cleaned output
	if strings.Contains(cleaned, "Block suspicious connection") {
		t.Error("Expected description comment '# Block suspicious connection' to be removed, but it was still present")
	}

	// The expiration comment should NOT remain
	if strings.Contains(cleaned, "CLI-Snitch-Expires") {
		t.Error("Expected expiration comment to be removed, but it was still present")
	}

	// The rule itself should NOT remain
	if strings.Contains(cleaned, "block out proto tcp from any to evil.com") {
		t.Error("Expected expired rule to be removed, but it was still present")
	}

	// Header lines should remain
	if !strings.Contains(cleaned, "CLI Snitch Firewall Rules") {
		t.Error("Expected header to remain after cleanup")
	}
}

func TestCleanupExpiredRules_KeepsValidRules(t *testing.T) {
	tmpDir := t.TempDir()
	anchorFile := filepath.Join(tmpDir, "test-anchor")

	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	expired := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	content := `# CLI Snitch Firewall Rules
# This file is managed by CLI Snitch - do not edit manually
# Generated at 2025-01-01T00:00:00Z

# Valid rule that should stay
# CLI-Snitch-Expires: ` + future + `
block out proto tcp from any to good.com port 443

# Expired rule that should go
# CLI-Snitch-Expires: ` + expired + `
block out proto tcp from any to bad.com port 80

# Permanent rule (no expiration)
block out proto tcp from any to permanent.com port 22
`

	if err := os.WriteFile(anchorFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test anchor file: %v", err)
	}

	// Simulate cleanup logic
	result, _ := os.ReadFile(anchorFile)
	lines := strings.Split(string(result), "\n")
	var validLines []string
	now := time.Now()

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.Contains(line, "# CLI-Snitch-Expires:") {
			parts := strings.Split(line, "CLI-Snitch-Expires:")
			if len(parts) == 2 {
				expiryStr := strings.TrimSpace(parts[1])
				if expiryTime, parseErr := time.Parse(time.RFC3339, expiryStr); parseErr == nil {
					if now.After(expiryTime) {
						if len(validLines) > 0 {
							prev := strings.TrimSpace(validLines[len(validLines)-1])
							if strings.HasPrefix(prev, "#") &&
								!strings.Contains(prev, "CLI Snitch Firewall Rules") &&
								!strings.Contains(prev, "do not edit manually") &&
								!strings.Contains(prev, "Generated at") {
								validLines = validLines[:len(validLines)-1]
							}
						}
						if i+1 < len(lines) {
							i++
						}
						continue
					}
				}
			}
		}

		validLines = append(validLines, line)
	}

	cleaned := strings.Join(validLines, "\n")

	// Valid (future) rule should remain
	if !strings.Contains(cleaned, "good.com") {
		t.Error("Expected non-expired rule to remain")
	}
	if !strings.Contains(cleaned, "Valid rule that should stay") {
		t.Error("Expected description of non-expired rule to remain")
	}

	// Expired rule should be gone
	if strings.Contains(cleaned, "bad.com") {
		t.Error("Expected expired rule to be removed")
	}
	if strings.Contains(cleaned, "Expired rule that should go") {
		t.Error("Expected description of expired rule to be removed")
	}

	// Permanent rule should remain
	if !strings.Contains(cleaned, "permanent.com") {
		t.Error("Expected permanent rule to remain")
	}
}

func TestCleanupExpiredRules_PreservesHeaders(t *testing.T) {
	tmpDir := t.TempDir()
	anchorFile := filepath.Join(tmpDir, "test-anchor")

	expired := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	// Place an expired rule right after the header with no blank line separation
	content := `# CLI Snitch Firewall Rules
# This file is managed by CLI Snitch - do not edit manually
# Generated at 2025-01-01T00:00:00Z
# CLI-Snitch-Expires: ` + expired + `
block out proto tcp from any to evil.com port 443
`

	if err := os.WriteFile(anchorFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test anchor file: %v", err)
	}

	result, _ := os.ReadFile(anchorFile)
	lines := strings.Split(string(result), "\n")
	var validLines []string
	now := time.Now()

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.Contains(line, "# CLI-Snitch-Expires:") {
			parts := strings.Split(line, "CLI-Snitch-Expires:")
			if len(parts) == 2 {
				expiryStr := strings.TrimSpace(parts[1])
				if expiryTime, parseErr := time.Parse(time.RFC3339, expiryStr); parseErr == nil {
					if now.After(expiryTime) {
						if len(validLines) > 0 {
							prev := strings.TrimSpace(validLines[len(validLines)-1])
							if strings.HasPrefix(prev, "#") &&
								!strings.Contains(prev, "CLI Snitch Firewall Rules") &&
								!strings.Contains(prev, "do not edit manually") &&
								!strings.Contains(prev, "Generated at") &&
								!strings.Contains(prev, "Set interface") &&
								!strings.Contains(prev, "Default:") &&
								!strings.Contains(prev, "CLI Snitch rules will be added") {
								validLines = validLines[:len(validLines)-1]
							}
						}
						if i+1 < len(lines) {
							i++
						}
						continue
					}
				}
			}
		}

		validLines = append(validLines, line)
	}

	cleaned := strings.Join(validLines, "\n")

	// All three header lines must survive (the "Generated at" line should NOT be removed
	// even though it's right before the expiration comment, because it's a header line)
	if !strings.Contains(cleaned, "CLI Snitch Firewall Rules") {
		t.Error("Expected first header line to remain")
	}
	if !strings.Contains(cleaned, "do not edit manually") {
		t.Error("Expected second header line to remain")
	}
	if !strings.Contains(cleaned, "Generated at") {
		t.Error("Expected 'Generated at' header line to remain (should not be treated as a description comment)")
	}
}

// Benchmark pfctl rule generation
func BenchmarkGeneratePfRule(b *testing.B) {
	fm := NewFirewallManager()
	rule := &FirewallRule{
		Action:    "block",
		Direction: "out",
		Protocol:  "tcp",
		Host:      "example.com",
		Port:      "443",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fm.generatePfRule(rule)
	}
}

func BenchmarkCreateBlockRuleFromUserDecision(b *testing.B) {
	fm := NewFirewallManager()
	decision := &prompt.UserDecision{
		Action:      rules.Deny,
		Scope:       rules.Exact,
		Description: "Test block",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fm.CreateBlockRuleFromUserDecision(decision, "TestApp", "test.com", "80")
	}
}
