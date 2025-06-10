package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	// Test console-only logger
	config := Config{
		Level:     INFO,
		Component: "test",
		Console:   true,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create console logger: %v", err)
	}
	defer logger.Close()
	
	if logger.level != INFO {
		t.Errorf("Expected level %v, got %v", INFO, logger.level)
	}
	
	if logger.component != "test" {
		t.Errorf("Expected component 'test', got '%s'", logger.component)
	}
}

func TestLoggerWithFile(t *testing.T) {
	// Create temporary log file
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")
	
	config := Config{
		Level:     DEBUG,
		Component: "filetest",
		Console:   false,
		LogFile:   logFile,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create file logger: %v", err)
	}
	defer logger.Close()
	
	// Test logging
	logger.Info("Test message")
	logger.Error("Test error")
	
	// Check if file was created and contains content
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Log file was not created")
	}
	
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	
	logContent := string(content)
	if !strings.Contains(logContent, "Test message") {
		t.Errorf("Log file does not contain expected info message")
	}
	
	if !strings.Contains(logContent, "Test error") {
		t.Errorf("Log file does not contain expected error message")
	}
}

func TestLogLevels(t *testing.T) {
	// Test log level filtering
	var buf bytes.Buffer
	
	config := Config{
		Level:     WARN,
		Component: "leveltest",
		Console:   true,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()
	
	// These should not be logged (below WARN level)
	logger.Debug("Debug message")
	logger.Info("Info message")
	
	// These should be logged (WARN level and above)
	logger.Warn("Warning message")
	logger.Error("Error message")
	
	// Note: Testing console output is complex, so we test the level logic
	if logger.shouldLog(DEBUG) {
		t.Errorf("DEBUG should not be logged when level is WARN")
	}
	
	if logger.shouldLog(INFO) {
		t.Errorf("INFO should not be logged when level is WARN")
	}
	
	if !logger.shouldLog(WARN) {
		t.Errorf("WARN should be logged when level is WARN")
	}
	
	if !logger.shouldLog(ERROR) {
		t.Errorf("ERROR should be logged when level is WARN")
	}
}

func TestLoggerMethods(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "methods.log")
	
	config := Config{
		Level:     DEBUG,
		Component: "methodtest",
		Console:   false,
		LogFile:   logFile,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()
	
	// Test different logging methods
	logger.Debug("Debug: %s", "formatted")
	logger.Info("Info: %d", 42)
	logger.Warn("Warning: %v", true)
	logger.Error("Error: %f", 3.14)
	
	// Test ErrorWithDetails
	testErr := &testError{"test error"}
	details := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}
	logger.ErrorWithDetails(testErr, "Context message", details)
	
	// Test WarnWithRecovery
	logger.WarnWithRecovery("Issue occurred", "Try this recovery")
	
	// Test InfoWithMetrics
	metrics := map[string]interface{}{
		"metric1": 100,
		"metric2": "success",
	}
	logger.InfoWithMetrics("Operation completed", metrics)
	
	// Verify file content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	
	logContent := string(content)
	
	expectedStrings := []string{
		"Debug: formatted",
		"Info: 42",
		"Warning: true",
		"Error: 3.14",
		"Context message: test error",
		"Recovery: Try this recovery",
		"Operation completed",
	}
	
	for _, expected := range expectedStrings {
		if !strings.Contains(logContent, expected) {
			t.Errorf("Log content missing expected string: %s", expected)
		}
	}
}

func TestLogRotation(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "rotate.log")
	
	config := Config{
		Level:     INFO,
		Component: "rotatetest",
		Console:   false,
		LogFile:   logFile,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()
	
	// Write some content
	logger.Info("Before rotation")
	
	// Rotate the log
	err = logger.Rotate()
	if err != nil {
		t.Fatalf("Failed to rotate log: %v", err)
	}
	
	// Write more content
	logger.Info("After rotation")
	
	// Check that original file exists with timestamp suffix
	files, err := filepath.Glob(logFile + ".*")
	if err != nil {
		t.Fatalf("Failed to glob rotated files: %v", err)
	}
	
	if len(files) != 1 {
		t.Errorf("Expected 1 rotated file, got %d", len(files))
	}
	
	// Check that new log file exists and contains new content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read new log file: %v", err)
	}
	
	if !strings.Contains(string(content), "After rotation") {
		t.Errorf("New log file does not contain expected content")
	}
	
	if strings.Contains(string(content), "Before rotation") {
		t.Errorf("New log file should not contain pre-rotation content")
	}
}

func TestSetLevel(t *testing.T) {
	config := Config{
		Level:     INFO,
		Component: "setleveltest",
		Console:   true,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()
	
	// Test initial level
	if logger.GetLevel() != INFO {
		t.Errorf("Expected initial level %v, got %v", INFO, logger.GetLevel())
	}
	
	// Change level
	logger.SetLevel(ERROR)
	
	if logger.GetLevel() != ERROR {
		t.Errorf("Expected updated level %v, got %v", ERROR, logger.GetLevel())
	}
	
	// Test that lower levels are now filtered
	if logger.shouldLog(WARN) {
		t.Errorf("WARN should not be logged when level is ERROR")
	}
}

func TestFormatMessage(t *testing.T) {
	config := Config{
		Level:     DEBUG,
		Component: "formattest",
		Console:   true,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()
	
	message := logger.formatMessage(INFO, "test message")
	
	// Check that formatted message contains expected components
	if !strings.Contains(message, "INFO") {
		t.Errorf("Formatted message should contain log level")
	}
	
	if !strings.Contains(message, "formattest") {
		t.Errorf("Formatted message should contain component name")
	}
	
	if !strings.Contains(message, "test message") {
		t.Errorf("Formatted message should contain actual message")
	}
	
	// Check timestamp format (should contain date and time)
	if !strings.Contains(message, time.Now().Format("2006-01-02")) {
		t.Errorf("Formatted message should contain current date")
	}
}

// testError is a simple error implementation for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestLoggerStringMethods(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
		{FATAL, "FATAL"},
	}
	
	for _, test := range tests {
		if test.level.String() != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, test.level.String())
		}
	}
	
	// Test unknown level
	unknownLevel := LogLevel(999)
	if unknownLevel.String() != "UNKNOWN" {
		t.Errorf("Expected UNKNOWN for invalid level, got %s", unknownLevel.String())
	}
} 