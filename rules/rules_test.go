package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuleManager_AddAndFindRule(t *testing.T) {
	// Create temp file for testing
	tempFile := filepath.Join(os.TempDir(), "test_rules.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	err := rm.LoadRules()
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Test adding a rule
	rule := Rule{
		ProcessName: "Chrome",
		Host:        "google.com",
		Port:        "443",
		Action:      Allow,
		Scope:       Exact,
		Description: "Allow Chrome to access Google",
	}

	err = rm.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Test finding the rule
	conn := ConnectionInfo{
		ProcessName: "Chrome",
		Host:        "google.com",
		Port:        "443",
	}

	foundRule, found := rm.FindMatchingRule(conn)
	if !found {
		t.Fatal("Expected to find matching rule")
	}

	if foundRule.Action != Allow {
		t.Errorf("Expected Allow action, got %v", foundRule.Action)
	}

	if foundRule.UseCount != 1 {
		t.Errorf("Expected UseCount 1, got %d", foundRule.UseCount)
	}
}

func TestRuleMatching_Scopes(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_scopes.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	// Add rules with different scopes
	rules := []Rule{
		{
			ProcessName: "Chrome",
			Action:      Allow,
			Scope:       ProcessOnly,
			Description: "Allow all Chrome connections",
		},
		{
			ProcessName: "Firefox",
			Host:        "mozilla.org",
			Action:      Deny,
			Scope:       ProcessAndHost,
			Description: "Deny Firefox to Mozilla",
		},
		{
			ProcessName: "Safari",
			Port:        "443",
			Action:      Allow,
			Scope:       ProcessAndPort,
			Description: "Allow Safari HTTPS",
		},
		{
			ProcessName: "curl",
			Host:        "example.com",
			Port:        "80",
			Action:      Deny,
			Scope:       Exact,
			Description: "Block curl to example.com:80",
		},
	}

	for _, rule := range rules {
		rm.AddRule(rule)
	}

	tests := []struct {
		name       string
		conn       ConnectionInfo
		shouldFind bool
		expected   Action
		desc       string
	}{
		{
			name: "Chrome ProcessOnly match",
			conn: ConnectionInfo{
				ProcessName: "Chrome",
				Host:        "anywhere.com",
				Port:        "8080",
			},
			shouldFind: true,
			expected:   Allow,
			desc:       "Should match Chrome regardless of host/port",
		},
		{
			name: "Firefox ProcessAndHost match",
			conn: ConnectionInfo{
				ProcessName: "Firefox",
				Host:        "mozilla.org",
				Port:        "443",
			},
			shouldFind: true,
			expected:   Deny,
			desc:       "Should match Firefox to mozilla.org",
		},
		{
			name: "Firefox ProcessAndHost no match",
			conn: ConnectionInfo{
				ProcessName: "Firefox",
				Host:        "google.com",
				Port:        "443",
			},
			shouldFind: false,
			desc:       "Should not match Firefox to different host",
		},
		{
			name: "Safari ProcessAndPort match",
			conn: ConnectionInfo{
				ProcessName: "Safari",
				Host:        "apple.com",
				Port:        "443",
			},
			shouldFind: true,
			expected:   Allow,
			desc:       "Should match Safari on port 443",
		},
		{
			name: "curl Exact match",
			conn: ConnectionInfo{
				ProcessName: "curl",
				Host:        "example.com",
				Port:        "80",
			},
			shouldFind: true,
			expected:   Deny,
			desc:       "Should match exact curl connection",
		},
		{
			name: "curl Exact no match - different port",
			conn: ConnectionInfo{
				ProcessName: "curl",
				Host:        "example.com",
				Port:        "8080",
			},
			shouldFind: false,
			desc:       "Should not match curl with different port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, found := rm.FindMatchingRule(tt.conn)
			
			if tt.shouldFind && !found {
				t.Errorf("Expected to find rule but didn't: %s", tt.desc)
			}
			
			if !tt.shouldFind && found {
				t.Errorf("Expected not to find rule but did: %s", tt.desc)
			}
			
			if found && rule.Action != tt.expected {
				t.Errorf("Expected action %v, got %v", tt.expected, rule.Action)
			}
		})
	}
}

func TestRulePersistence(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_persistence.json")
	defer os.Remove(tempFile)

	// Create first rule manager and add rules
	rm1 := NewRuleManager(tempFile)
	rm1.LoadRules()

	rule := Rule{
		ProcessName: "TestApp",
		Host:        "test.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
		Description: "Test rule for persistence",
	}

	err := rm1.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Create second rule manager and load rules
	rm2 := NewRuleManager(tempFile)
	err = rm2.LoadRules()
	if err != nil {
		t.Fatalf("Failed to load rules in second manager: %v", err)
	}

	// Check if rule was persisted
	conn := ConnectionInfo{
		ProcessName: "TestApp",
		Host:        "test.com",
		Port:        "any",
	}

	foundRule, found := rm2.FindMatchingRule(conn)
	if !found {
		t.Fatal("Rule was not persisted correctly")
	}

	if foundRule.ProcessName != "TestApp" {
		t.Errorf("Expected ProcessName TestApp, got %s", foundRule.ProcessName)
	}

	if foundRule.Action != Allow {
		t.Errorf("Expected Allow action, got %v", foundRule.Action)
	}
}

func TestRuleManager_DeleteRule(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_delete.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	// Add a rule
	rule := Rule{
		ProcessName: "DeleteMe",
		Action:      Allow,
		Scope:       ProcessOnly,
	}

	err := rm.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Verify it exists
	rules := rm.GetAllRules()
	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	ruleID := rules[0].ID

	// Delete the rule
	err = rm.DeleteRule(ruleID)
	if err != nil {
		t.Fatalf("Failed to delete rule: %v", err)
	}

	// Verify it's gone
	rules = rm.GetAllRules()
	if len(rules) != 0 {
		t.Fatalf("Expected 0 rules after deletion, got %d", len(rules))
	}
}

func TestRuleStats(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_stats.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	// Add some rules
	rules := []Rule{
		{ProcessName: "App1", Action: Allow, Scope: ProcessOnly},
		{ProcessName: "App1", Action: Deny, Scope: ProcessAndHost, Host: "bad.com"},
		{ProcessName: "App2", Action: Allow, Scope: Exact, Host: "good.com", Port: "443"},
	}

	for _, rule := range rules {
		rm.AddRule(rule)
	}

	stats := rm.GetRuleStats()

	if stats["total_rules"] != 3 {
		t.Errorf("Expected 3 total rules, got %v", stats["total_rules"])
	}

	if stats["allow_rules"] != 2 {
		t.Errorf("Expected 2 allow rules, got %v", stats["allow_rules"])
	}

	if stats["deny_rules"] != 1 {
		t.Errorf("Expected 1 deny rule, got %v", stats["deny_rules"])
	}

	byProcess := stats["by_process"].(map[string]int)
	if byProcess["App1"] != 2 {
		t.Errorf("Expected 2 rules for App1, got %d", byProcess["App1"])
	}
	if byProcess["App2"] != 1 {
		t.Errorf("Expected 1 rule for App2, got %d", byProcess["App2"])
	}
}

func TestCaseInsensitiveMatching(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_case.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rule := Rule{
		ProcessName: "Chrome",
		Host:        "Google.Com",
		Port:        "HTTPS",
		Action:      Allow,
		Scope:       Exact,
	}

	rm.AddRule(rule)

	// Test with different cases
	conn := ConnectionInfo{
		ProcessName: "chrome",
		Host:        "google.com",
		Port:        "https",
	}

	foundRule, found := rm.FindMatchingRule(conn)
	if !found {
		t.Fatal("Case-insensitive matching failed")
	}

	if foundRule.Action != Allow {
		t.Errorf("Expected Allow, got %v", foundRule.Action)
	}
}

func TestRuleID_Generation(t *testing.T) {
	rule1 := Rule{
		ProcessName: "Test App",
		Host:        "example.com",
		Port:        "443",
		Action:      Allow,
		Scope:       Exact,
	}

	rule2 := Rule{
		ProcessName: "Test App",
		Host:        "example.com",
		Port:        "443",
		Action:      Allow,
		Scope:       Exact,
	}

	id1 := generateRuleID(rule1)
	time.Sleep(1 * time.Second) // Ensure different timestamps
	id2 := generateRuleID(rule2)

	if id1 == id2 {
		t.Error("Rule IDs should be unique even for similar rules")
	}

	if id1 == "" || id2 == "" {
		t.Error("Rule IDs should not be empty")
	}
} 