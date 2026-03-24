package prompt

import (
	"context"
	"testing"
	"time"

	"cli-snitch/monitor"
	"cli-snitch/rules"
)

func TestNewConnectionPrompter(t *testing.T) {
	prompter := NewConnectionPrompter(true)
	if prompter == nil {
		t.Fatal("NewConnectionPrompter returned nil")
	}

	if !prompter.interactive {
		t.Error("Expected interactive mode to be true")
	}

	// Test non-interactive mode
	nonInteractivePrompter := NewConnectionPrompter(false)
	if nonInteractivePrompter.interactive {
		t.Error("Expected interactive mode to be false")
	}
}

func TestPromptForDecision_NonInteractive(t *testing.T) {
	prompter := NewConnectionPrompter(false)

	conn := &monitor.Connection{
		PID:         1234,
		ProcessName: "TestApp",
		RemoteAddr:  "example.com",
		RemotePort:  "443",
		Timestamp:   time.Now(),
	}

	decision, err := prompter.PromptForDecision(conn)
	if err != nil {
		t.Fatalf("Expected no error in non-interactive mode, got %v", err)
	}

	if decision.Action != rules.AllowOnce {
		t.Errorf("Expected AllowOnce action in non-interactive mode, got %v", decision.Action)
	}

	if decision.Scope != rules.Exact {
		t.Errorf("Expected Exact scope in non-interactive mode, got %v", decision.Scope)
	}

	expectedDesc := "Auto-allowed in non-interactive mode"
	if decision.Description != expectedDesc {
		t.Errorf("Expected description '%s', got '%s'", expectedDesc, decision.Description)
	}
}

func TestGenerateDescription(t *testing.T) {
	prompter := NewConnectionPrompter(true)

	conn := &monitor.Connection{
		ProcessName: "Chrome",
		RemoteAddr:  "google.com",
		RemotePort:  "443",
	}

	tests := []struct {
		action   rules.Action
		scope    rules.RuleScope
		expected string
	}{
		{
			action:   rules.Allow,
			scope:    rules.Exact,
			expected: "Allow Chrome to connect to google.com:443",
		},
		{
			action:   rules.Deny,
			scope:    rules.ProcessAndHost,
			expected: "Deny Chrome to connect to google.com (any port)",
		},
		{
			action:   rules.Allow,
			scope:    rules.ProcessAndPort,
			expected: "Allow Chrome to connect to port 443 (any host)",
		},
		{
			action:   rules.Deny,
			scope:    rules.ProcessOnly,
			expected: "Deny all Chrome network connections",
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.action)+"_"+string(tt.scope), func(t *testing.T) {
			result := prompter.generateDescription(tt.action, tt.scope, conn)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestGetHostInfo(t *testing.T) {
	prompter := NewConnectionPrompter(true)

	tests := []struct {
		addr     string
		expected string
	}{
		{"142.250.123.45", "Google Services"},
		{"172.217.100.1", "Google Services"},
		{"13.56.78.90", "Amazon Web Services (AWS)"},
		{"54.123.45.67", "Amazon Web Services (AWS)"},
		{"3.45.67.89", "Amazon Web Services (AWS)"},
		{"104.16.123.45", "Cloudflare"},
		{"172.64.45.67", "Cloudflare"},
		{"185.199.108.133", "GitHub/Microsoft"},
		{"192.168.1.1", "Local Network"},
		{"10.0.0.1", "Local Network"},
		{"172.16.0.1", "Local Network"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := prompter.getHostInfo(tt.addr)
			if result != tt.expected {
				t.Errorf("For %s, expected '%s', got '%s'", tt.addr, tt.expected, result)
			}
		})
	}
}

func TestGetHostInfo_DNSCache(t *testing.T) {
	prompter := NewConnectionPrompter(true)

	// Pre-populate the DNS cache
	prompter.dnsCache.Store("99.99.99.99", "cached.example.com")

	result := prompter.getHostInfo("99.99.99.99")
	if result != "cached.example.com" {
		t.Errorf("Expected cached DNS result 'cached.example.com', got '%s'", result)
	}

	// Verify that an empty cached result returns empty string without re-lookup
	prompter.dnsCache.Store("99.99.99.98", "")
	result = prompter.getHostInfo("99.99.99.98")
	if result != "" {
		t.Errorf("Expected empty string for cached empty DNS result, got '%s'", result)
	}
}

func TestConfirmBulkAction(t *testing.T) {
	prompter := NewConnectionPrompter(true)

	// Test with single connection (should return true without prompting)
	confirm, err := prompter.ConfirmBulkAction(1, "TestApp")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !confirm {
		t.Error("Expected true for single connection")
	}

	// Test with zero connections (should return true without prompting)
	confirm, err = prompter.ConfirmBulkAction(0, "TestApp")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !confirm {
		t.Error("Expected true for zero connections")
	}

	// For multiple connections, we can't easily test the interactive prompt
	// without mocking the survey library, so we'll skip that test case
}

func TestUserDecisionStruct(t *testing.T) {
	decision := &UserDecision{
		Action:      rules.Allow,
		Scope:       rules.ProcessOnly,
		Description: "Test description",
	}

	if decision.Action != rules.Allow {
		t.Errorf("Expected Allow action, got %v", decision.Action)
	}

	if decision.Scope != rules.ProcessOnly {
		t.Errorf("Expected ProcessOnly scope, got %v", decision.Scope)
	}

	if decision.Description != "Test description" {
		t.Errorf("Expected 'Test description', got '%s'", decision.Description)
	}
}

// Mock connection for testing display functionality
func createMockConnection() *monitor.Connection {
	return &monitor.Connection{
		PID:         12345,
		ProcessName: "TestBrowser",
		User:        "testuser",
		Protocol:    "tcp",
		LocalAddr:   "192.168.1.100",
		LocalPort:   "54321",
		RemoteAddr:  "142.250.123.45",
		RemotePort:  "443",
		State:       "ESTABLISHED",
		Timestamp:   time.Now(),
	}
}

func TestDisplayConnectionInfo(t *testing.T) {
	prompter := NewConnectionPrompter(true)
	conn := createMockConnection()

	// This test primarily checks that the function runs without error
	// In a real implementation, you might capture stdout to verify output
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("displayConnectionInfo panicked: %v", r)
		}
	}()

	prompter.displayConnectionInfo(conn)
	// If we get here without panicking, the test passes
}

func TestDisplayRuleSummary(t *testing.T) {
	prompter := NewConnectionPrompter(true)

	decision := &UserDecision{
		Action:      rules.Allow,
		Scope:       rules.ProcessOnly,
		Description: "Allow all TestBrowser connections",
	}

	rule := &rules.Rule{
		ID:          "test-rule-123",
		ProcessName: "TestBrowser",
		Action:      rules.Allow,
		Scope:       rules.ProcessOnly,
	}

	// This test primarily checks that the function runs without error
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("DisplayRuleSummary panicked: %v", r)
		}
	}()

	prompter.DisplayRuleSummary(decision, rule)
	// If we get here without panicking, the test passes
}

func TestQueuePrompt_NonInteractive(t *testing.T) {
	prompter := NewConnectionPrompter(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	prompter.StartPromptWorker(ctx)
	defer prompter.StopPromptWorker()

	conn := &monitor.Connection{
		PID:         1234,
		ProcessName: "TestApp",
		RemoteAddr:  "example.com",
		RemotePort:  "443",
		Timestamp:   time.Now(),
	}

	// Send multiple prompts concurrently to verify serialization
	results := make(chan *UserDecision, 3)
	errs := make(chan error, 3)

	for i := 0; i < 3; i++ {
		go func() {
			decision, err := prompter.QueuePrompt(conn)
			if err != nil {
				errs <- err
				return
			}
			results <- decision
		}()
	}

	for i := 0; i < 3; i++ {
		select {
		case decision := <-results:
			if decision.Action != rules.AllowOnce {
				t.Errorf("Expected AllowOnce, got %v", decision.Action)
			}
			if decision.Description != "Auto-allowed in non-interactive mode" {
				t.Errorf("Unexpected description: %s", decision.Description)
			}
		case err := <-errs:
			t.Fatalf("QueuePrompt returned error: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timed out waiting for queued prompt result")
		}
	}
}
