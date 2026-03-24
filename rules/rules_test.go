package rules

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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

// --- New tests ---

func TestConcurrentAccess(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_concurrent.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	// Seed with a rule
	rm.AddRule(Rule{
		ProcessName: "ConcApp",
		Host:        "example.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
	})

	var wg sync.WaitGroup
	const goroutines = 20

	// Half the goroutines read, half write
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				rm.FindMatchingRule(ConnectionInfo{
					ProcessName: "ConcApp",
					Host:        "example.com",
					Port:        "443",
				})
			}()
		} else {
			go func(n int) {
				defer wg.Done()
				rm.AddRule(Rule{
					ProcessName: "ConcApp",
					Host:        "other.com",
					Action:      Deny,
					Scope:       ProcessAndHost,
					Description: "concurrent rule",
				})
			}(i)
		}
	}

	wg.Wait()

	// Verify no panic occurred and rules are consistent
	allRules := rm.GetAllRules()
	if len(allRules) < 1 {
		t.Fatal("Expected at least 1 rule after concurrent access")
	}
}

func TestConcurrentReadsDontBlock(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_concurrent_reads.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "ReadApp",
		Host:        "read.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
	})

	var wg sync.WaitGroup
	const readers = 50

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rm.GetAllRules()
			rm.FindMatchingRule(ConnectionInfo{
				ProcessName: "ReadApp",
				Host:        "read.com",
				Port:        "443",
			})
			rm.GetRuleStats()
		}()
	}

	wg.Wait()
}

func TestFlushIfDirty(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_flush.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "FlushApp",
		Host:        "flush.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
	})

	// FlushIfDirty should be a no-op right after AddRule (which already saved)
	err := rm.FlushIfDirty()
	if err != nil {
		t.Fatalf("FlushIfDirty failed: %v", err)
	}

	// Trigger a match to set dirty=true
	rm.FindMatchingRule(ConnectionInfo{
		ProcessName: "FlushApp",
		Host:        "flush.com",
		Port:        "443",
	})

	// Now flush should actually write
	err = rm.FlushIfDirty()
	if err != nil {
		t.Fatalf("FlushIfDirty after match failed: %v", err)
	}

	// Verify persisted use count by loading in a new manager
	rm2 := NewRuleManager(tempFile)
	rm2.LoadRules()
	allRules := rm2.GetAllRules()
	if len(allRules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(allRules))
	}
	if allRules[0].UseCount != 1 {
		t.Errorf("Expected UseCount 1 after flush, got %d", allRules[0].UseCount)
	}
}

func TestExportRules(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_export.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "ExportApp",
		Host:        "export.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
	})
	rm.AddRule(Rule{
		ProcessName: "ExportApp2",
		Host:        "export2.com",
		Action:      Deny,
		Scope:       Exact,
		Port:        "80",
	})

	var buf bytes.Buffer
	err := rm.ExportRules(&buf)
	if err != nil {
		t.Fatalf("ExportRules failed: %v", err)
	}

	// Verify the output is valid JSON containing our rules
	var exported []Rule
	if err := json.Unmarshal(buf.Bytes(), &exported); err != nil {
		t.Fatalf("Exported JSON is invalid: %v", err)
	}

	if len(exported) != 2 {
		t.Fatalf("Expected 2 exported rules, got %d", len(exported))
	}
	if exported[0].ProcessName != "ExportApp" {
		t.Errorf("Expected ExportApp, got %s", exported[0].ProcessName)
	}
}

func TestImportRules_Replace(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_import_replace.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "OldApp",
		Action:      Allow,
		Scope:       ProcessOnly,
	})

	// Import new rules, replacing existing
	importData := []Rule{
		{ID: "imp1", ProcessName: "NewApp1", Action: Allow, Scope: ProcessOnly},
		{ID: "imp2", ProcessName: "NewApp2", Action: Deny, Scope: ProcessOnly},
	}
	data, _ := json.Marshal(importData)

	err := rm.ImportRules(bytes.NewReader(data), false)
	if err != nil {
		t.Fatalf("ImportRules failed: %v", err)
	}

	allRules := rm.GetAllRules()
	if len(allRules) != 2 {
		t.Fatalf("Expected 2 rules after replace import, got %d", len(allRules))
	}
	if allRules[0].ProcessName != "NewApp1" {
		t.Errorf("Expected NewApp1, got %s", allRules[0].ProcessName)
	}
}

func TestImportRules_Merge(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_import_merge.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "ExistingApp",
		Action:      Allow,
		Scope:       ProcessOnly,
	})

	importData := []Rule{
		{ID: "imp1", ProcessName: "MergedApp", Action: Deny, Scope: ProcessOnly},
	}
	data, _ := json.Marshal(importData)

	err := rm.ImportRules(bytes.NewReader(data), true)
	if err != nil {
		t.Fatalf("ImportRules merge failed: %v", err)
	}

	allRules := rm.GetAllRules()
	if len(allRules) != 2 {
		t.Fatalf("Expected 2 rules after merge import, got %d", len(allRules))
	}
}

func TestImportExportRoundTrip(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_roundtrip.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "RoundTrip",
		Host:        "rt.com",
		Port:        "443",
		Action:      Allow,
		Scope:       Exact,
		Description: "round trip test",
	})

	// Export
	var buf bytes.Buffer
	rm.ExportRules(&buf)

	// Import into a fresh manager
	tempFile2 := filepath.Join(os.TempDir(), "test_roundtrip2.json")
	defer os.Remove(tempFile2)

	rm2 := NewRuleManager(tempFile2)
	rm2.LoadRules()

	err := rm2.ImportRules(bytes.NewReader(buf.Bytes()), false)
	if err != nil {
		t.Fatalf("Import after export failed: %v", err)
	}

	allRules := rm2.GetAllRules()
	if len(allRules) != 1 {
		t.Fatalf("Expected 1 rule after round trip, got %d", len(allRules))
	}
	if allRules[0].ProcessName != "RoundTrip" {
		t.Errorf("Expected RoundTrip, got %s", allRules[0].ProcessName)
	}
	if allRules[0].Description != "round trip test" {
		t.Errorf("Expected description preserved, got %s", allRules[0].Description)
	}
}

func TestUpdateRule(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_update.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "UpdateMe",
		Host:        "old.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
		Description: "original",
	})

	allRules := rm.GetAllRules()
	if len(allRules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(allRules))
	}
	ruleID := allRules[0].ID

	// Update several fields
	err := rm.UpdateRule(ruleID, Rule{
		Host:        "new.com",
		Action:      Deny,
		Description: "updated",
	})
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	allRules = rm.GetAllRules()
	updated := allRules[0]
	if updated.Host != "new.com" {
		t.Errorf("Expected host new.com, got %s", updated.Host)
	}
	if updated.Action != Deny {
		t.Errorf("Expected Deny action, got %v", updated.Action)
	}
	if updated.Description != "updated" {
		t.Errorf("Expected description 'updated', got %s", updated.Description)
	}
	// ProcessName should be unchanged
	if updated.ProcessName != "UpdateMe" {
		t.Errorf("Expected ProcessName UpdateMe, got %s", updated.ProcessName)
	}
}

func TestUpdateRule_NotFound(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_update_nf.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	err := rm.UpdateRule("nonexistent", Rule{Host: "x.com"})
	if err == nil {
		t.Fatal("Expected error for nonexistent rule ID")
	}
}

func TestWildcardMatching(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_wildcard.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	// Add a rule with a glob pattern
	rm.AddRule(Rule{
		ProcessName: "Chrome",
		Pattern:     "*.google.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
		Description: "Allow all Google subdomains",
	})

	tests := []struct {
		name       string
		host       string
		shouldFind bool
	}{
		{"matches www.google.com", "www.google.com", true},
		{"matches mail.google.com", "mail.google.com", true},
		{"matches MAPS.Google.Com (case insensitive)", "MAPS.Google.Com", true},
		{"does not match google.com (no subdomain)", "google.com", false},
		{"does not match www.bing.com", "www.bing.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, found := rm.FindMatchingRule(ConnectionInfo{
				ProcessName: "Chrome",
				Host:        tt.host,
				Port:        "443",
			})
			if found != tt.shouldFind {
				t.Errorf("host %q: expected found=%v, got %v", tt.host, tt.shouldFind, found)
			}
		})
	}
}

func TestWildcardMatching_ExactScope(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_wildcard_exact.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	rm.AddRule(Rule{
		ProcessName: "curl",
		Pattern:     "*.example.*",
		Port:        "443",
		Action:      Deny,
		Scope:       Exact,
	})

	// Should match: pattern matches host AND port matches
	_, found := rm.FindMatchingRule(ConnectionInfo{
		ProcessName: "curl",
		Host:        "www.example.org",
		Port:        "443",
	})
	if !found {
		t.Error("Expected wildcard match with Exact scope and matching port")
	}

	// Should not match: pattern matches host but port differs
	_, found = rm.FindMatchingRule(ConnectionInfo{
		ProcessName: "curl",
		Host:        "www.example.org",
		Port:        "80",
	})
	if found {
		t.Error("Should not match when port differs in Exact scope")
	}
}

func TestPatternFallsBackToHost(t *testing.T) {
	tempFile := filepath.Join(os.TempDir(), "test_pattern_fallback.json")
	defer os.Remove(tempFile)

	rm := NewRuleManager(tempFile)
	rm.LoadRules()

	// Rule with Host set but no Pattern -- should still match by Host
	rm.AddRule(Rule{
		ProcessName: "Safari",
		Host:        "apple.com",
		Action:      Allow,
		Scope:       ProcessAndHost,
	})

	_, found := rm.FindMatchingRule(ConnectionInfo{
		ProcessName: "Safari",
		Host:        "apple.com",
		Port:        "443",
	})
	if !found {
		t.Error("Expected host-based match when Pattern is empty")
	}
}
