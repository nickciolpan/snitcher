package errors

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- ErrorBuilder tests ---

func TestErrorBuilder_Basic(t *testing.T) {
	err := NewError(ErrorTypeSystem, SeverityHigh, "something broke").Build()

	if err.Type != ErrorTypeSystem {
		t.Errorf("expected type %s, got %s", ErrorTypeSystem, err.Type)
	}
	if err.Severity != SeverityHigh {
		t.Errorf("expected severity %s, got %s", SeverityHigh, err.Severity)
	}
	if err.Message != "something broke" {
		t.Errorf("unexpected message: %s", err.Message)
	}
	if err.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestErrorBuilder_WithCause(t *testing.T) {
	cause := fmt.Errorf("root cause")
	err := NewError(ErrorTypeNetwork, SeverityMedium, "net fail").
		WithCause(cause).
		Build()

	if err.Cause != cause {
		t.Errorf("cause not set correctly")
	}
}

func TestErrorBuilder_WithContext(t *testing.T) {
	err := NewError(ErrorTypeConfig, SeverityLow, "bad config").
		WithContext("file", "/etc/foo").
		WithContext("line", 42).
		Build()

	if err.Context["file"] != "/etc/foo" {
		t.Errorf("context 'file' not set")
	}
	if err.Context["line"] != 42 {
		t.Errorf("context 'line' not set")
	}
}

func TestErrorBuilder_WithComponent(t *testing.T) {
	err := NewError(ErrorTypeMonitor, SeverityMedium, "monitor fail").
		WithComponent("monitor-service").
		Build()

	if err.Component != "monitor-service" {
		t.Errorf("component not set: %s", err.Component)
	}
}

func TestErrorBuilder_WithStackTrace(t *testing.T) {
	err := NewError(ErrorTypeSystem, SeverityHigh, "crash").
		WithStackTrace().
		Build()

	if err.StackTrace == "" {
		t.Error("stack trace should not be empty")
	}
	if !strings.Contains(err.StackTrace, "errors_test.go") {
		t.Error("stack trace should reference the test file")
	}
}

func TestErrorBuilder_WithRecovery(t *testing.T) {
	err := NewError(ErrorTypeNetwork, SeverityMedium, "timeout").
		WithRecovery("retry later").
		Build()

	if !err.Recoverable {
		t.Error("error should be recoverable")
	}
	if err.Recovery != "retry later" {
		t.Errorf("unexpected recovery: %s", err.Recovery)
	}
}

// --- Error types and severity ---

func TestErrorTypes(t *testing.T) {
	types := []ErrorType{
		ErrorTypeSystem, ErrorTypeNetwork, ErrorTypeFirewall,
		ErrorTypePermission, ErrorTypeRule, ErrorTypePrompt,
		ErrorTypeConfig, ErrorTypeMonitor, ErrorTypeValidation,
		ErrorTypeParsing, ErrorTypeStorage,
	}
	for _, et := range types {
		if et == "" {
			t.Error("error type should not be empty")
		}
	}
}

func TestSeverityLevels(t *testing.T) {
	levels := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, s := range levels {
		if s == "" {
			t.Error("severity should not be empty")
		}
	}
}

func TestIsType(t *testing.T) {
	err := NewError(ErrorTypeFirewall, SeverityHigh, "fw").Build()
	if !err.IsType(ErrorTypeFirewall) {
		t.Error("IsType should return true for matching type")
	}
	if err.IsType(ErrorTypeNetwork) {
		t.Error("IsType should return false for non-matching type")
	}
}

func TestIsSeverity(t *testing.T) {
	err := NewError(ErrorTypeSystem, SeverityCritical, "crit").Build()
	if !err.IsSeverity(SeverityCritical) {
		t.Error("IsSeverity should return true for matching severity")
	}
	if err.IsSeverity(SeverityLow) {
		t.Error("IsSeverity should return false for non-matching severity")
	}
}

// --- Predefined error constructors ---

func TestNewSystemError(t *testing.T) {
	cause := fmt.Errorf("disk full")
	err := NewSystemError("system failure", cause)
	if err.Type != ErrorTypeSystem {
		t.Errorf("expected system type, got %s", err.Type)
	}
	if err.Severity != SeverityHigh {
		t.Errorf("expected high severity, got %s", err.Severity)
	}
	if err.Cause != cause {
		t.Error("cause not set")
	}
	if err.StackTrace == "" {
		t.Error("system errors should have stack traces")
	}
}

func TestNewNetworkError(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	err := NewNetworkError("net down", cause)
	if err.Type != ErrorTypeNetwork {
		t.Errorf("expected network type, got %s", err.Type)
	}
	if !err.Recoverable {
		t.Error("network errors should be recoverable")
	}
}

func TestNewFirewallError(t *testing.T) {
	cause := fmt.Errorf("pfctl failed")
	err := NewFirewallError("firewall issue", cause)
	if err.Type != ErrorTypeFirewall {
		t.Errorf("expected firewall type, got %s", err.Type)
	}
	if !err.Recoverable {
		t.Error("firewall errors should be recoverable")
	}
}

func TestNewPermissionError(t *testing.T) {
	err := NewPermissionError("access denied", "write")
	if err.Type != ErrorTypePermission {
		t.Errorf("expected permission type, got %s", err.Type)
	}
	if err.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", err.Severity)
	}
	if err.Context["operation"] != "write" {
		t.Error("operation context not set")
	}
}

func TestNewRuleError(t *testing.T) {
	cause := fmt.Errorf("bad syntax")
	err := NewRuleError("rule parse failed", cause)
	if err.Type != ErrorTypeRule {
		t.Errorf("expected rule type, got %s", err.Type)
	}
}

func TestNewMonitorError(t *testing.T) {
	cause := fmt.Errorf("socket closed")
	err := NewMonitorError("monitor stopped", cause)
	if err.Type != ErrorTypeMonitor {
		t.Errorf("expected monitor type, got %s", err.Type)
	}
}

func TestNewValidationError(t *testing.T) {
	err := NewValidationError("port", 99999, "port out of range")
	if err.Type != ErrorTypeValidation {
		t.Errorf("expected validation type, got %s", err.Type)
	}
	if err.Context["field"] != "port" {
		t.Error("field context not set")
	}
	if err.Context["value"] != 99999 {
		t.Error("value context not set")
	}
}

func TestNewConfigError(t *testing.T) {
	err := NewConfigError("bad config", "/etc/snitch.yaml")
	if err.Type != ErrorTypeConfig {
		t.Errorf("expected config type, got %s", err.Type)
	}
	if err.Context["config_path"] != "/etc/snitch.yaml" {
		t.Error("config_path context not set")
	}
}

func TestNewParsingError(t *testing.T) {
	cause := fmt.Errorf("unexpected token")
	err := NewParsingError("parse fail", "foo=bar=baz", cause)
	if err.Type != ErrorTypeParsing {
		t.Errorf("expected parsing type, got %s", err.Type)
	}
	if err.Context["input"] != "foo=bar=baz" {
		t.Error("input context not set")
	}
}

// --- ErrorHandler submit and handle ---

func TestErrorHandler_SubmitAndHandle(t *testing.T) {
	handler := NewErrorHandler()

	var handled []*CLISnitchError
	var mu sync.Mutex

	handler.RegisterHandler(ErrorTypeSystem, func(err *CLISnitchError) {
		mu.Lock()
		handled = append(handled, err)
		mu.Unlock()
	})

	handler.Start()

	sysErr := NewError(ErrorTypeSystem, SeverityHigh, "test error").Build()
	handler.Submit(sysErr)

	// Wait briefly for async processing
	time.Sleep(100 * time.Millisecond)
	handler.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(handled) != 1 {
		t.Errorf("expected 1 handled error, got %d", len(handled))
	}
	if len(handled) > 0 && handled[0].Message != "test error" {
		t.Errorf("unexpected message: %s", handled[0].Message)
	}
}

// --- ErrorHandler close drains pending errors ---

func TestErrorHandler_CloseDrainsPending(t *testing.T) {
	handler := NewErrorHandler()

	count := 0
	var mu sync.Mutex

	handler.RegisterHandler(ErrorTypeNetwork, func(err *CLISnitchError) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	handler.Start()

	// Submit multiple errors
	for i := 0; i < 50; i++ {
		handler.Submit(NewError(ErrorTypeNetwork, SeverityMedium, fmt.Sprintf("error %d", i)).Build())
	}

	handler.Close()

	mu.Lock()
	defer mu.Unlock()
	if count != 50 {
		t.Errorf("expected 50 errors drained, got %d", count)
	}
}

func TestErrorHandler_DoubleCloseNoPanic(t *testing.T) {
	handler := NewErrorHandler()
	handler.Start()

	// Should not panic
	handler.Close()
	handler.Close()
}

// --- RecoveryManager ---

func TestRecoveryManager_DefaultStrategies(t *testing.T) {
	rm := NewRecoveryManager()

	networkStrategies := rm.GetStrategies(ErrorTypeNetwork)
	if len(networkStrategies) == 0 {
		t.Error("expected default network strategies")
	}

	monitorStrategies := rm.GetStrategies(ErrorTypeMonitor)
	if len(monitorStrategies) == 0 {
		t.Error("expected default monitor strategies")
	}

	firewallStrategies := rm.GetStrategies(ErrorTypeFirewall)
	if len(firewallStrategies) == 0 {
		t.Error("expected default firewall strategies")
	}
}

func TestRecoveryManager_AttemptRecovery_Success(t *testing.T) {
	rm := NewRecoveryManager()

	callCount := 0
	rm.AddStrategy(ErrorTypeSystem, &RecoveryStrategy{
		Name:        "test_recovery",
		Description: "test recovery action",
		MaxRetries:  3,
		Action: func() error {
			callCount++
			return nil // succeed immediately
		},
	})

	err := NewError(ErrorTypeSystem, SeverityHigh, "recoverable").Build()
	recoveryErr := rm.AttemptRecovery(err)

	if recoveryErr != nil {
		t.Errorf("expected successful recovery, got: %v", recoveryErr)
	}
	if callCount != 1 {
		t.Errorf("expected action called once, got %d", callCount)
	}
}

func TestRecoveryManager_AttemptRecovery_Failure(t *testing.T) {
	rm := NewRecoveryManager()

	callCount := 0
	rm.AddStrategy(ErrorTypeSystem, &RecoveryStrategy{
		Name:       "failing_recovery",
		MaxRetries: 1,
		Action: func() error {
			callCount++
			return fmt.Errorf("still failing")
		},
	})

	err := NewError(ErrorTypeSystem, SeverityHigh, "unrecoverable").Build()
	recoveryErr := rm.AttemptRecovery(err)

	if recoveryErr == nil {
		t.Error("expected recovery failure")
	}
	if callCount != 1 {
		t.Errorf("expected action called 1 time, got %d", callCount)
	}
}

func TestRecoveryManager_AttemptRecovery_NoAction(t *testing.T) {
	rm := NewRecoveryManager()

	// Default strategies have nil actions, so all should fail
	err := NewError(ErrorTypeNetwork, SeverityMedium, "net error").Build()
	recoveryErr := rm.AttemptRecovery(err)

	if recoveryErr == nil {
		t.Error("expected failure when strategies have no actions")
	}
}

// --- CLISnitchError.Error() and String() ---

func TestCLISnitchError_Error_WithCause(t *testing.T) {
	cause := fmt.Errorf("root cause")
	err := NewError(ErrorTypeSystem, SeverityHigh, "something failed").
		WithCause(cause).
		Build()

	s := err.Error()
	if !strings.Contains(s, "[SYSTEM:HIGH]") {
		t.Errorf("error string missing type:severity prefix: %s", s)
	}
	if !strings.Contains(s, "something failed") {
		t.Errorf("error string missing message: %s", s)
	}
	if !strings.Contains(s, "root cause") {
		t.Errorf("error string missing cause: %s", s)
	}
}

func TestCLISnitchError_Error_WithoutCause(t *testing.T) {
	err := NewError(ErrorTypeNetwork, SeverityMedium, "timeout").Build()

	s := err.Error()
	if !strings.Contains(s, "[NETWORK:MEDIUM]") {
		t.Errorf("error string missing type:severity prefix: %s", s)
	}
	if !strings.Contains(s, "timeout") {
		t.Errorf("error string missing message: %s", s)
	}
}

func TestCLISnitchError_String(t *testing.T) {
	err := NewError(ErrorTypeFirewall, SeverityCritical, "blocked").
		WithComponent("firewall-svc").
		WithContext("rule_id", "123").
		WithRecovery("check pfctl").
		Build()

	s := err.String()

	checks := []string{
		"Type: FIREWALL",
		"Severity: CRITICAL",
		"Component: firewall-svc",
		"Recoverable: true",
		"Recovery: check pfctl",
		"rule_id: 123",
	}

	for _, check := range checks {
		if !strings.Contains(s, check) {
			t.Errorf("String() output missing %q:\n%s", check, s)
		}
	}
}

func TestCLISnitchError_String_WithStackTrace(t *testing.T) {
	err := NewError(ErrorTypeSystem, SeverityHigh, "crash").
		WithStackTrace().
		Build()

	s := err.String()
	if !strings.Contains(s, "Stack Trace:") {
		t.Error("String() should include stack trace section")
	}
}
