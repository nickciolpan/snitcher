package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging capabilities for CLI Snitch
type Logger struct {
	level     LogLevel
	logFile   *os.File
	infoLog   *log.Logger
	warnLog   *log.Logger
	errorLog  *log.Logger
	debugLog  *log.Logger
	component string
}

// Config holds logger configuration
type Config struct {
	Level     LogLevel
	LogFile   string
	Component string
	Console   bool
}

// NewLogger creates a new logger instance with the specified configuration
func NewLogger(config Config) (*Logger, error) {
	logger := &Logger{
		level:     config.Level,
		component: config.Component,
	}

	var writers []io.Writer

	// Always include console output if enabled
	if config.Console {
		writers = append(writers, os.Stdout)
	}

	// Setup file logging if specified
	if config.LogFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %v", err)
		}

		// Open log file with append mode
		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logger.logFile = file
		writers = append(writers, file)
	}

	// Create multi-writer for output
	var output io.Writer
	if len(writers) > 1 {
		output = io.MultiWriter(writers...)
	} else if len(writers) == 1 {
		output = writers[0]
	} else {
		output = os.Stdout // Fallback to stdout
	}

	// Setup different loggers for different levels
	logger.debugLog = log.New(output, "", log.LstdFlags|log.Lmicroseconds)
	logger.infoLog = log.New(output, "", log.LstdFlags)
	logger.warnLog = log.New(output, "", log.LstdFlags)
	logger.errorLog = log.New(output, "", log.LstdFlags)

	return logger, nil
}

// Close closes the logger and any open file handles
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// shouldLog determines if a message should be logged based on the current level
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.level
}

// formatMessage formats a log message with timestamp, level, component, and message
func (l *Logger) formatMessage(level LogLevel, message string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	return fmt.Sprintf("[%s] %s [%s] %s", timestamp, level.String(), l.component, message)
}

// formatConsoleMessage formats a message for console output with colors
func (l *Logger) formatConsoleMessage(level LogLevel, message string) string {
	var levelColor func(a ...interface{}) string
	var emoji string

	switch level {
	case DEBUG:
		levelColor = color.New(color.FgHiBlack).SprintFunc()
		emoji = "🔍"
	case INFO:
		levelColor = color.New(color.FgCyan).SprintFunc()
		emoji = "ℹ️"
	case WARN:
		levelColor = color.New(color.FgYellow).SprintFunc()
		emoji = "⚠️"
	case ERROR:
		levelColor = color.New(color.FgRed).SprintFunc()
		emoji = "❌"
	case FATAL:
		levelColor = color.New(color.FgRed, color.Bold).SprintFunc()
		emoji = "💀"
	default:
		levelColor = color.New(color.Reset).SprintFunc()
		emoji = "📝"
	}

	component := color.New(color.Faint).Sprintf("[%s]", l.component)
	return fmt.Sprintf("%s %s %s %s", emoji, levelColor(level.String()), component, message)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if !l.shouldLog(DEBUG) {
		return
	}
	message := fmt.Sprintf(format, args...)
	l.debugLog.Print(l.formatConsoleMessage(DEBUG, message))
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if !l.shouldLog(INFO) {
		return
	}
	message := fmt.Sprintf(format, args...)
	l.infoLog.Print(l.formatConsoleMessage(INFO, message))
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if !l.shouldLog(WARN) {
		return
	}
	message := fmt.Sprintf(format, args...)
	l.warnLog.Print(l.formatConsoleMessage(WARN, message))
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if !l.shouldLog(ERROR) {
		return
	}
	message := fmt.Sprintf(format, args...)
	l.errorLog.Print(l.formatConsoleMessage(ERROR, message))
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	l.errorLog.Print(l.formatConsoleMessage(FATAL, message))
	if l.logFile != nil {
		l.logFile.Close()
	}
	os.Exit(1)
}

// ErrorWithDetails logs an error with additional context details
func (l *Logger) ErrorWithDetails(err error, context string, details map[string]interface{}) {
	if !l.shouldLog(ERROR) {
		return
	}
	
	message := fmt.Sprintf("%s: %v", context, err)
	if len(details) > 0 {
		message += " | Details: "
		for key, value := range details {
			message += fmt.Sprintf("%s=%v ", key, value)
		}
	}
	
	l.errorLog.Print(l.formatConsoleMessage(ERROR, message))
}

// WarnWithRecovery logs a warning with recovery suggestion
func (l *Logger) WarnWithRecovery(issue string, recovery string) {
	if !l.shouldLog(WARN) {
		return
	}
	message := fmt.Sprintf("%s | Recovery: %s", issue, recovery)
	l.warnLog.Print(l.formatConsoleMessage(WARN, message))
}

// InfoWithMetrics logs info with performance metrics
func (l *Logger) InfoWithMetrics(message string, metrics map[string]interface{}) {
	if !l.shouldLog(INFO) {
		return
	}
	
	fullMessage := message
	if len(metrics) > 0 {
		fullMessage += " | Metrics: "
		for key, value := range metrics {
			fullMessage += fmt.Sprintf("%s=%v ", key, value)
		}
	}
	
	l.infoLog.Print(l.formatConsoleMessage(INFO, fullMessage))
}

// SetLevel updates the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

// Rotate rotates the log file if it exists
func (l *Logger) Rotate() error {
	if l.logFile == nil {
		return nil
	}

	// Close current file
	if err := l.logFile.Close(); err != nil {
		return fmt.Errorf("failed to close current log file: %v", err)
	}

	// Rename current file with timestamp
	oldPath := l.logFile.Name()
	timestamp := time.Now().Format("20060102_150405")
	newPath := fmt.Sprintf("%s.%s", oldPath, timestamp)
	
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("failed to rotate log file: %v", err)
	}

	// Open new file
	file, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open new log file: %v", err)
	}
	
	l.logFile = file

	// Update all internal loggers to write to the new file
	l.debugLog.SetOutput(file)
	l.infoLog.SetOutput(file)
	l.warnLog.SetOutput(file)
	l.errorLog.SetOutput(file)

	l.Info("Log file rotated successfully")

	return nil
}

// RotateIfNeeded rotates the log file if it exceeds maxSizeMB megabytes.
func (l *Logger) RotateIfNeeded(maxSizeMB int) error {
	if l.logFile == nil {
		return nil
	}
	info, err := l.logFile.Stat()
	if err != nil {
		return err
	}
	if info.Size() > int64(maxSizeMB)*1024*1024 {
		return l.Rotate()
	}
	return nil
} 