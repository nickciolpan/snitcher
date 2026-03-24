package errors

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ErrorType represents different categories of errors in CLI Snitch
type ErrorType string

const (
	// System errors
	ErrorTypeSystem     ErrorType = "SYSTEM"
	ErrorTypeNetwork    ErrorType = "NETWORK"
	ErrorTypeFirewall   ErrorType = "FIREWALL"
	ErrorTypePermission ErrorType = "PERMISSION"
	
	// Application errors
	ErrorTypeRule       ErrorType = "RULE"
	ErrorTypePrompt     ErrorType = "PROMPT"
	ErrorTypeConfig     ErrorType = "CONFIG"
	ErrorTypeMonitor    ErrorType = "MONITOR"
	
	// Data errors
	ErrorTypeValidation ErrorType = "VALIDATION"
	ErrorTypeParsing    ErrorType = "PARSING"
	ErrorTypeStorage    ErrorType = "STORAGE"
)

// Severity represents the severity level of an error
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// CLISnitchError represents an error with context and metadata
type CLISnitchError struct {
	Type        ErrorType              `json:"type"`
	Severity    Severity               `json:"severity"`
	Message     string                 `json:"message"`
	Cause       error                  `json:"cause,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
	Component   string                 `json:"component"`
	Recoverable bool                   `json:"recoverable"`
	Recovery    string                 `json:"recovery,omitempty"`
}

// Error implements the error interface
func (e *CLISnitchError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Type, e.Severity, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Severity, e.Message)
}

// String provides a detailed string representation
func (e *CLISnitchError) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Error: %s\n", e.Error()))
	sb.WriteString(fmt.Sprintf("Type: %s\n", e.Type))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", e.Severity))
	sb.WriteString(fmt.Sprintf("Component: %s\n", e.Component))
	sb.WriteString(fmt.Sprintf("Time: %s\n", e.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Recoverable: %t\n", e.Recoverable))
	
	if e.Recovery != "" {
		sb.WriteString(fmt.Sprintf("Recovery: %s\n", e.Recovery))
	}
	
	if len(e.Context) > 0 {
		sb.WriteString("Context:\n")
		for key, value := range e.Context {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
		}
	}
	
	if e.StackTrace != "" {
		sb.WriteString(fmt.Sprintf("Stack Trace:\n%s\n", e.StackTrace))
	}
	
	return sb.String()
}

// IsType checks if the error is of a specific type
func (e *CLISnitchError) IsType(errorType ErrorType) bool {
	return e.Type == errorType
}

// IsSeverity checks if the error has a specific severity
func (e *CLISnitchError) IsSeverity(severity Severity) bool {
	return e.Severity == severity
}

// ErrorBuilder helps construct CLISnitchError instances
type ErrorBuilder struct {
	error *CLISnitchError
}

// NewError creates a new error builder
func NewError(errorType ErrorType, severity Severity, message string) *ErrorBuilder {
	return &ErrorBuilder{
		error: &CLISnitchError{
			Type:      errorType,
			Severity:  severity,
			Message:   message,
			Context:   make(map[string]interface{}),
			Timestamp: time.Now(),
		},
	}
}

// WithCause adds the underlying cause
func (eb *ErrorBuilder) WithCause(cause error) *ErrorBuilder {
	eb.error.Cause = cause
	return eb
}

// WithContext adds context information
func (eb *ErrorBuilder) WithContext(key string, value interface{}) *ErrorBuilder {
	eb.error.Context[key] = value
	return eb
}

// WithComponent sets the component name
func (eb *ErrorBuilder) WithComponent(component string) *ErrorBuilder {
	eb.error.Component = component
	return eb
}

// WithStackTrace captures the current stack trace
func (eb *ErrorBuilder) WithStackTrace() *ErrorBuilder {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	eb.error.StackTrace = string(buf[:n])
	return eb
}

// WithRecovery marks the error as recoverable and provides recovery instructions
func (eb *ErrorBuilder) WithRecovery(recovery string) *ErrorBuilder {
	eb.error.Recoverable = true
	eb.error.Recovery = recovery
	return eb
}

// Build returns the constructed error
func (eb *ErrorBuilder) Build() *CLISnitchError {
	return eb.error
}

// Predefined error constructors for common scenarios

// NewSystemError creates a new system-level error
func NewSystemError(message string, cause error) *CLISnitchError {
	return NewError(ErrorTypeSystem, SeverityHigh, message).
		WithCause(cause).
		WithStackTrace().
		Build()
}

// NewNetworkError creates a new network-related error
func NewNetworkError(message string, cause error) *CLISnitchError {
	return NewError(ErrorTypeNetwork, SeverityMedium, message).
		WithCause(cause).
		WithRecovery("Check network connectivity and retry").
		Build()
}

// NewFirewallError creates a new firewall-related error
func NewFirewallError(message string, cause error) *CLISnitchError {
	return NewError(ErrorTypeFirewall, SeverityHigh, message).
		WithCause(cause).
		WithRecovery("Check pfctl availability and permissions").
		Build()
}

// NewPermissionError creates a new permission-related error
func NewPermissionError(message string, operation string) *CLISnitchError {
	return NewError(ErrorTypePermission, SeverityCritical, message).
		WithContext("operation", operation).
		WithRecovery("Run with sudo or check file permissions").
		Build()
}

// NewRuleError creates a new rule-related error
func NewRuleError(message string, cause error) *CLISnitchError {
	return NewError(ErrorTypeRule, SeverityMedium, message).
		WithCause(cause).
		WithRecovery("Check rule syntax and configuration").
		Build()
}

// NewMonitorError creates a new monitoring-related error
func NewMonitorError(message string, cause error) *CLISnitchError {
	return NewError(ErrorTypeMonitor, SeverityMedium, message).
		WithCause(cause).
		WithRecovery("Restart monitoring service").
		Build()
}

// NewValidationError creates a new validation error
func NewValidationError(field string, value interface{}, message string) *CLISnitchError {
	return NewError(ErrorTypeValidation, SeverityLow, message).
		WithContext("field", field).
		WithContext("value", value).
		WithRecovery("Correct the input and try again").
		Build()
}

// NewConfigError creates a new configuration error
func NewConfigError(message string, configPath string) *CLISnitchError {
	return NewError(ErrorTypeConfig, SeverityMedium, message).
		WithContext("config_path", configPath).
		WithRecovery("Check configuration file syntax and permissions").
		Build()
}

// NewParsingError creates a new parsing error
func NewParsingError(message string, input string, cause error) *CLISnitchError {
	return NewError(ErrorTypeParsing, SeverityLow, message).
		WithCause(cause).
		WithContext("input", input).
		WithRecovery("Check input format and syntax").
		Build()
}

// ErrorHandler provides centralized error handling capabilities
type ErrorHandler struct {
	errorChan chan *CLISnitchError
	handlers  map[ErrorType]func(*CLISnitchError)
	done      chan struct{}
	once      sync.Once
}

// NewErrorHandler creates a new error handler
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		errorChan: make(chan *CLISnitchError, 100),
		handlers:  make(map[ErrorType]func(*CLISnitchError)),
		done:      make(chan struct{}),
	}
}

// RegisterHandler registers a handler for a specific error type
func (eh *ErrorHandler) RegisterHandler(errorType ErrorType, handler func(*CLISnitchError)) {
	eh.handlers[errorType] = handler
}

// Handle processes an error
func (eh *ErrorHandler) Handle(err *CLISnitchError) {
	if handler, exists := eh.handlers[err.Type]; exists {
		handler(err)
	} else {
		// Default handling
		fmt.Printf("Unhandled error: %s\n", err.Error())
	}
}

// Start begins error processing
func (eh *ErrorHandler) Start() {
	go func() {
		defer close(eh.done)
		for err := range eh.errorChan {
			eh.Handle(err)
		}
	}()
}

// Submit submits an error for processing
func (eh *ErrorHandler) Submit(err *CLISnitchError) {
	select {
	case eh.errorChan <- err:
	default:
		// Channel is full, handle synchronously
		eh.Handle(err)
	}
}

// Close closes the error handler and waits for pending errors to drain
func (eh *ErrorHandler) Close() {
	eh.once.Do(func() {
		close(eh.errorChan)
	})
	select {
	case <-eh.done:
	case <-time.After(5 * time.Second):
	}
}

// Recovery strategies

// RecoveryStrategy represents a recovery action
type RecoveryStrategy struct {
	Name        string
	Description string
	Action      func() error
	MaxRetries  int
}

// RecoveryManager manages error recovery strategies
type RecoveryManager struct {
	strategies map[ErrorType][]*RecoveryStrategy
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager() *RecoveryManager {
	rm := &RecoveryManager{
		strategies: make(map[ErrorType][]*RecoveryStrategy),
	}
	
	// Register default recovery strategies
	rm.registerDefaultStrategies()
	
	return rm
}

// registerDefaultStrategies registers built-in recovery strategies
func (rm *RecoveryManager) registerDefaultStrategies() {
	// Network error recovery
	rm.AddStrategy(ErrorTypeNetwork, &RecoveryStrategy{
		Name:        "network_retry",
		Description: "Retry network operation with exponential backoff",
		MaxRetries:  3,
	})
	
	// Monitor error recovery
	rm.AddStrategy(ErrorTypeMonitor, &RecoveryStrategy{
		Name:        "monitor_restart",
		Description: "Restart monitoring service",
		MaxRetries:  2,
	})
	
	// Firewall error recovery
	rm.AddStrategy(ErrorTypeFirewall, &RecoveryStrategy{
		Name:        "firewall_reinit",
		Description: "Reinitialize firewall connection",
		MaxRetries:  1,
	})
}

// AddStrategy adds a recovery strategy for an error type
func (rm *RecoveryManager) AddStrategy(errorType ErrorType, strategy *RecoveryStrategy) {
	rm.strategies[errorType] = append(rm.strategies[errorType], strategy)
}

// GetStrategies returns recovery strategies for an error type
func (rm *RecoveryManager) GetStrategies(errorType ErrorType) []*RecoveryStrategy {
	return rm.strategies[errorType]
}

// AttemptRecovery attempts to recover from an error
func (rm *RecoveryManager) AttemptRecovery(err *CLISnitchError) error {
	strategies := rm.GetStrategies(err.Type)
	
	for _, strategy := range strategies {
		if strategy.Action != nil {
			for attempt := 0; attempt < strategy.MaxRetries; attempt++ {
				if recoveryErr := strategy.Action(); recoveryErr == nil {
					return nil // Recovery successful
				}
				time.Sleep(time.Duration(attempt+1) * time.Second) // Exponential backoff
			}
		}
	}
	
	return fmt.Errorf("all recovery strategies failed for error type: %s", err.Type)
} 