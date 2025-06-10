package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Action represents what to do with a connection
type Action string

const (
	Allow      Action = "allow"
	Deny       Action = "deny"
	AllowOnce  Action = "allow_once"
	DenyOnce   Action = "deny_once"
)

// RuleScope defines how broad the rule should be
type RuleScope string

const (
	ProcessOnly    RuleScope = "process"           // Match only this process
	ProcessAndHost RuleScope = "process_host"     // Match process + specific host
	ProcessAndPort RuleScope = "process_port"     // Match process + specific port
	Exact          RuleScope = "exact"            // Match process + host + port exactly
)

// Rule represents a user decision about network connections
type Rule struct {
	ID          string    `json:"id"`
	ProcessName string    `json:"process_name"`
	Host        string    `json:"host,omitempty"`        // IP or domain name
	Port        string    `json:"port,omitempty"`        // Port number or service name
	Action      Action    `json:"action"`
	Scope       RuleScope `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used,omitempty"`
	UseCount    int       `json:"use_count"`
	Description string    `json:"description,omitempty"` // User-friendly description
}

// ConnectionInfo represents the connection details to match against rules
type ConnectionInfo struct {
	ProcessName string
	Host        string
	Port        string
}

// RuleManager handles loading, saving, and matching rules
type RuleManager struct {
	rules    []Rule
	filePath string
}

// NewRuleManager creates a new rule manager
func NewRuleManager(filePath string) *RuleManager {
	return &RuleManager{
		rules:    make([]Rule, 0),
		filePath: filePath,
	}
}

// LoadRules loads rules from the JSON file
func (rm *RuleManager) LoadRules() error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(rm.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(rm.filePath); os.IsNotExist(err) {
		// File doesn't exist, start with empty rules
		rm.rules = make([]Rule, 0)
		return nil
	}

	// Read and parse the file
	data, err := os.ReadFile(rm.filePath)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %v", err)
	}

	if len(data) == 0 {
		// Empty file, start with empty rules
		rm.rules = make([]Rule, 0)
		return nil
	}

	if err := json.Unmarshal(data, &rm.rules); err != nil {
		return fmt.Errorf("failed to parse rules file: %v", err)
	}

	return nil
}

// SaveRules saves rules to the JSON file
func (rm *RuleManager) SaveRules() error {
	data, err := json.MarshalIndent(rm.rules, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %v", err)
	}

	if err := os.WriteFile(rm.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write rules file: %v", err)
	}

	return nil
}

// AddRule adds a new rule and saves it
func (rm *RuleManager) AddRule(rule Rule) error {
	// Generate ID if not provided
	if rule.ID == "" {
		rule.ID = generateRuleID(rule)
	}

	// Set creation time
	rule.CreatedAt = time.Now()
	rule.UseCount = 0

	// Add to rules list
	rm.rules = append(rm.rules, rule)

	// Save to file
	return rm.SaveRules()
}

// FindMatchingRule finds the first rule that matches the connection
func (rm *RuleManager) FindMatchingRule(conn ConnectionInfo) (*Rule, bool) {
	for i := range rm.rules {
		rule := &rm.rules[i]
		if rm.matchesRule(rule, conn) {
			// Update usage statistics
			rule.LastUsed = time.Now()
			rule.UseCount++
			
			// Skip saving for "once" actions to avoid persistence
			if rule.Action != AllowOnce && rule.Action != DenyOnce {
				rm.SaveRules() // Save updated usage stats
			}
			
			return rule, true
		}
	}
	return nil, false
}

// matchesRule checks if a connection matches a specific rule
func (rm *RuleManager) matchesRule(rule *Rule, conn ConnectionInfo) bool {
	// Process name must always match (case-insensitive)
	if !strings.EqualFold(rule.ProcessName, conn.ProcessName) {
		return false
	}

	switch rule.Scope {
	case ProcessOnly:
		// Only process name needs to match
		return true

	case ProcessAndHost:
		// Process and host must match
		return strings.EqualFold(rule.Host, conn.Host)

	case ProcessAndPort:
		// Process and port must match
		return strings.EqualFold(rule.Port, conn.Port)

	case Exact:
		// Process, host, and port must all match
		return strings.EqualFold(rule.Host, conn.Host) && 
			   strings.EqualFold(rule.Port, conn.Port)

	default:
		return false
	}
}

// GetAllRules returns all rules
func (rm *RuleManager) GetAllRules() []Rule {
	return rm.rules
}

// DeleteRule removes a rule by ID
func (rm *RuleManager) DeleteRule(id string) error {
	for i, rule := range rm.rules {
		if rule.ID == id {
			// Remove rule from slice
			rm.rules = append(rm.rules[:i], rm.rules[i+1:]...)
			return rm.SaveRules()
		}
	}
	return fmt.Errorf("rule with ID %s not found", id)
}

// ClearRules removes all rules
func (rm *RuleManager) ClearRules() error {
	rm.rules = make([]Rule, 0)
	return rm.SaveRules()
}

// generateRuleID creates a unique ID for a rule
func generateRuleID(rule Rule) string {
	// Create ID based on rule components
	components := []string{rule.ProcessName}
	
	if rule.Host != "" {
		components = append(components, rule.Host)
	}
	if rule.Port != "" {
		components = append(components, rule.Port)
	}
	
	components = append(components, string(rule.Action), string(rule.Scope))
	
	// Create a simple hash-like ID
	id := strings.Join(components, "_")
	id = strings.ReplaceAll(id, " ", "-")
	id = strings.ToLower(id)
	
	// Add timestamp to ensure uniqueness
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	
	return fmt.Sprintf("%s_%s", id, timestamp)
}

// GetRuleStats returns statistics about rules
func (rm *RuleManager) GetRuleStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_rules": len(rm.rules),
		"allow_rules": 0,
		"deny_rules":  0,
		"by_scope":    make(map[RuleScope]int),
		"by_process":  make(map[string]int),
	}

	for _, rule := range rm.rules {
		// Count by action
		if rule.Action == Allow {
			stats["allow_rules"] = stats["allow_rules"].(int) + 1
		} else if rule.Action == Deny {
			stats["deny_rules"] = stats["deny_rules"].(int) + 1
		}

		// Count by scope
		scopeMap := stats["by_scope"].(map[RuleScope]int)
		scopeMap[rule.Scope]++

		// Count by process
		processMap := stats["by_process"].(map[string]int)
		processMap[rule.ProcessName]++
	}

	return stats
} 