package firewall

import (
	"testing"
	"time"
	
	"cli-snitch/rules"
	"cli-snitch/prompt"
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
			result := fm.generatePfRule(tt.rule)
			if result != tt.expected {
				t.Errorf("generatePfRule() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestCreateBlockRuleFromUserDecision(t *testing.T) {
	fm := NewFirewallManager()
	
	tests := []struct {
		name        string
		decision    *prompt.UserDecision
		processName string
		host        string
		port        string
		expectHost  string
		expectPort  string
		expectExpiry bool
	}{
		{
			name: "deny once with exact scope",
			decision: &prompt.UserDecision{
				Action:      rules.DenyOnce,
				Scope:       rules.Exact,
				Description: "Block Chrome to Google",
			},
			processName: "Chrome",
			host:        "google.com",
			port:        "443",
			expectHost:  "google.com",
			expectPort:  "443",
			expectExpiry: true,
		},
		{
			name: "deny always with process and host scope",
			decision: &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       rules.ProcessAndHost,
				Description: "Block app to specific host",
			},
			processName: "TestApp",
			host:        "badsite.com",
			port:        "80",
			expectHost:  "badsite.com",
			expectPort:  "",
			expectExpiry: false,
		},
		{
			name: "deny with process and port scope",
			decision: &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       rules.ProcessAndPort,
				Description: "Block app on specific port",
			},
			processName: "TestApp",
			host:        "example.com",
			port:        "22",
			expectHost:  "",
			expectPort:  "22",
			expectExpiry: false,
		},
		{
			name: "deny with process only scope",
			decision: &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       rules.ProcessOnly,
				Description: "Block process completely",
			},
			processName: "BadApp",
			host:        "anywhere.com",
			port:        "80",
			expectHost:  "anywhere.com", // pfctl needs at least host/port, so we use host
			expectPort:  "",
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
	pfRule := fm.generatePfRule(firewallRule)
	
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
		_ = fm.generatePfRule(rule)
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