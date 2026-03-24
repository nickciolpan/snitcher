package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cli-snitch/prompt"
	"cli-snitch/rules"
)

var (
	hostPattern = regexp.MustCompile(`^[a-zA-Z0-9._:\-]+$`)
	portPattern = regexp.MustCompile(`^[0-9]+$`)
)

// FirewallManager handles pfctl firewall integration
type FirewallManager struct {
	anchorName    string
	anchorFile    string
	configFile    string
	enabled       bool
}

// FirewallRule represents a pfctl rule
type FirewallRule struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`      // "block" or "pass"
	Direction   string    `json:"direction"`   // "in" or "out"
	Interface   string    `json:"interface"`   // network interface
	Protocol    string    `json:"protocol"`    // "tcp", "udp", "icmp"
	ProcessName string    `json:"process_name"`
	Host        string    `json:"host"`
	Port        string    `json:"port"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // For temporary rules
}

// NewFirewallManager creates a new firewall manager
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		anchorName: "cli-snitch",
		anchorFile: "/etc/pf.anchors/cli-snitch",
		configFile: "/etc/pf.cli-snitch.conf",
		enabled:    false,
	}
}

// Initialize sets up the firewall system
func (fm *FirewallManager) Initialize() error {
	// Check if we're running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("firewall operations require root privileges")
	}
	
	// Create anchor directory if it doesn't exist
	anchorDir := filepath.Dir(fm.anchorFile)
	if err := os.MkdirAll(anchorDir, 0755); err != nil {
		return fmt.Errorf("failed to create anchor directory: %v", err)
	}
	
	// Create initial anchor file
	if err := fm.createAnchorFile(); err != nil {
		return fmt.Errorf("failed to create anchor file: %v", err)
	}
	
	// Create config file that loads our anchor
	if err := fm.createConfigFile(); err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	
	return nil
}

// createAnchorFile creates the initial anchor file with basic structure
func (fm *FirewallManager) createAnchorFile() error {
	content := `# CLI Snitch Firewall Rules
# This file is managed by CLI Snitch - do not edit manually
# Generated at ` + time.Now().Format(time.RFC3339) + `

# Set interface (adjust as needed)
ext_if = "en0"

# Default: allow all traffic (CLI Snitch will add specific blocks)
# CLI Snitch rules will be added below this line

`
	
	return os.WriteFile(fm.anchorFile, []byte(content), 0644)
}

// createConfigFile creates a config file that loads our anchor
func (fm *FirewallManager) createConfigFile() error {
	content := fmt.Sprintf(`# CLI Snitch pfctl configuration
# Load CLI Snitch anchor
anchor "%s"
load anchor "%s" from "%s"
`, fm.anchorName, fm.anchorName, fm.anchorFile)

	return os.WriteFile(fm.configFile, []byte(content), 0644)
}

// Enable activates the firewall with our rules
func (fm *FirewallManager) Enable() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("firewall enable requires root privileges")
	}
	
	// Load our configuration
	cmd := exec.Command("pfctl", "-f", fm.configFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to load pfctl config: %v\nOutput: %s", err, string(output))
	}
	
	// Enable pfctl
	cmd = exec.Command("pfctl", "-E")
	if output, err := cmd.CombinedOutput(); err != nil {
		// pfctl -E may return error if already enabled, check if it's actually an error
		if !strings.Contains(string(output), "pf enabled") && 
		   !strings.Contains(string(output), "pfctl: pf already enabled") {
			return fmt.Errorf("failed to enable pfctl: %v\nOutput: %s", err, string(output))
		}
	}
	
	fm.enabled = true
	return nil
}

// Disable deactivates the firewall
func (fm *FirewallManager) Disable() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("firewall disable requires root privileges")
	}
	
	cmd := exec.Command("pfctl", "-d")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable pfctl: %v\nOutput: %s", err, string(output))
	}
	
	fm.enabled = false
	return nil
}

// AddBlockRule adds a blocking rule for a connection
func (fm *FirewallManager) AddBlockRule(rule *FirewallRule) error {
	if err := fm.validateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %v", err)
	}
	
	// Generate pfctl rule syntax
	pfRule, err := fm.generatePfRule(rule)
	if err != nil {
		return fmt.Errorf("failed to generate pf rule: %v", err)
	}

	// Add rule to anchor file with expiration if applicable
	if err := fm.appendRuleToAnchor(pfRule, rule.Description, rule.ExpiresAt); err != nil {
		return fmt.Errorf("failed to add rule to anchor: %v", err)
	}
	
	// Reload the anchor
	if err := fm.reloadAnchor(); err != nil {
		return fmt.Errorf("failed to reload anchor: %v", err)
	}
	
	return nil
}

// sanitizeValue validates a host or port value for safe use in pfctl rules.
// For hosts, only alphanumeric characters, dots, colons, hyphens, and underscores are allowed.
// For ports, only numeric characters are allowed.
func sanitizeValue(value string, isPort bool) (string, error) {
	if value == "" {
		return "", nil
	}
	if isPort {
		if !portPattern.MatchString(value) {
			return "", fmt.Errorf("invalid port value %q: only numeric characters allowed", value)
		}
	} else {
		if !hostPattern.MatchString(value) {
			return "", fmt.Errorf("invalid host value %q: only alphanumeric, dots, colons, hyphens, and underscores allowed", value)
		}
	}
	return value, nil
}

// generatePfRule creates pfctl rule syntax from our rule structure.
// It sanitizes host and port values before building the command string.
func (fm *FirewallManager) generatePfRule(rule *FirewallRule) (string, error) {
	// Sanitize host and port values
	host, err := sanitizeValue(rule.Host, false)
	if err != nil {
		return "", fmt.Errorf("host sanitization failed: %w", err)
	}
	port, err := sanitizeValue(rule.Port, true)
	if err != nil {
		return "", fmt.Errorf("port sanitization failed: %w", err)
	}

	var parts []string

	// Action
	parts = append(parts, rule.Action)

	// Direction
	if rule.Direction != "" {
		parts = append(parts, rule.Direction)
	}

	// Interface (if specified)
	if rule.Interface != "" {
		parts = append(parts, "on", rule.Interface)
	}

	// Protocol
	if rule.Protocol != "" {
		parts = append(parts, "proto", rule.Protocol)
	}

	// Source/destination based on direction
	if rule.Direction == "out" {
		// Outbound: from any to destination
		parts = append(parts, "from", "any", "to")
		if host != "" && port != "" {
			parts = append(parts, host, "port", port)
		} else if host != "" {
			parts = append(parts, host)
		} else if port != "" {
			parts = append(parts, "any", "port", port)
		} else {
			parts = append(parts, "any")
		}
	} else {
		// Inbound or unspecified: from source to any
		parts = append(parts, "from")
		if host != "" && port != "" {
			parts = append(parts, host, "port", port)
		} else if host != "" {
			parts = append(parts, host)
		} else {
			parts = append(parts, "any")
		}
		parts = append(parts, "to", "any")
	}

	return strings.Join(parts, " "), nil
}

// appendRuleToAnchor adds a rule to the anchor file with optional expiration
func (fm *FirewallManager) appendRuleToAnchor(pfRule, description string, expiresAt *time.Time) error {
	// Read current content
	content, err := os.ReadFile(fm.anchorFile)
	if err != nil {
		return err
	}
	
	// Add new rule with comment and optional expiration
	var newRule string
	if expiresAt != nil {
		newRule = fmt.Sprintf("\n# %s\n# CLI-Snitch-Expires: %s\n%s\n", 
			description, expiresAt.Format(time.RFC3339), pfRule)
	} else {
		newRule = fmt.Sprintf("\n# %s\n%s\n", description, pfRule)
	}
	
	// Write back
	return os.WriteFile(fm.anchorFile, append(content, []byte(newRule)...), 0644)
}

// reloadAnchor reloads the anchor rules into pfctl
func (fm *FirewallManager) reloadAnchor() error {
	cmd := exec.Command("pfctl", "-a", fm.anchorName, "-f", fm.anchorFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload anchor: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// validateRule checks if a rule is valid
func (fm *FirewallManager) validateRule(rule *FirewallRule) error {
	if rule.Action != "block" && rule.Action != "pass" {
		return fmt.Errorf("invalid action: %s (must be 'block' or 'pass')", rule.Action)
	}
	
	if rule.Direction != "" && rule.Direction != "in" && rule.Direction != "out" {
		return fmt.Errorf("invalid direction: %s (must be 'in', 'out', or empty)", rule.Direction)
	}
	
	if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
		return fmt.Errorf("invalid protocol: %s (must be 'tcp', 'udp', 'icmp', or empty)", rule.Protocol)
	}
	
	return nil
}

// CreateBlockRuleFromUserDecision creates a firewall rule from a user decision
func (fm *FirewallManager) CreateBlockRuleFromUserDecision(decision *prompt.UserDecision, processName, host, port string) *FirewallRule {
	rule := &FirewallRule{
		ID:          fmt.Sprintf("cli-snitch-%d", time.Now().UnixNano()),
		Action:      "block",
		Direction:   "out", // Block outbound connections
		Interface:   "",    // Apply to all interfaces
		Protocol:    "tcp", // Most connections are TCP
		ProcessName: processName,
		Description: decision.Description,
		CreatedAt:   time.Now(),
	}
	
	// Set destination based on rule scope
	switch decision.Scope {
	case rules.ProcessOnly:
		// Can't block just by process with pfctl - need at least host or port
		// Use host to make it more specific
		rule.Host = host
	case rules.ProcessAndHost:
		rule.Host = host
	case rules.ProcessAndPort:
		rule.Port = port
	case rules.Exact:
		rule.Host = host
		rule.Port = port
	}
	
	// Set expiration for "Once" actions
	if decision.Action == rules.DenyOnce {
		expiry := time.Now().Add(24 * time.Hour) // Expire after 24 hours
		rule.ExpiresAt = &expiry
	}
	
	return rule
}

// GetStatus returns the current firewall status
func (fm *FirewallManager) GetStatus() (map[string]interface{}, error) {
	status := make(map[string]interface{})
	
	// Check if pfctl is enabled
	cmd := exec.Command("pfctl", "-s", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		status["enabled"] = false
		status["error"] = fmt.Sprintf("Failed to get pfctl status: %v", err)
		return status, nil
	}
	
	outputStr := string(output)
	status["enabled"] = strings.Contains(outputStr, "Status: Enabled")
	status["raw_output"] = outputStr
	
	// Check if our anchor is loaded
	cmd = exec.Command("pfctl", "-a", fm.anchorName, "-s", "rules")
	output, err = cmd.CombinedOutput()
	if err == nil {
		status["anchor_loaded"] = true
		status["rules_count"] = len(strings.Split(strings.TrimSpace(string(output)), "\n"))
	} else {
		status["anchor_loaded"] = false
		status["anchor_error"] = err.Error()
	}
	
	return status, nil
}

// ListRules returns all current firewall rules in our anchor
func (fm *FirewallManager) ListRules() ([]string, error) {
	cmd := exec.Command("pfctl", "-a", fm.anchorName, "-s", "rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if the error is because the anchor doesn't exist
		if strings.Contains(string(output), "Invalid argument") || 
		   strings.Contains(err.Error(), "No such file or directory") {
			// Anchor doesn't exist yet - return empty list
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to list rules: %v", err)
	}
	
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var rules []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Filter out system messages and empty lines
		if line != "" && 
		   !strings.Contains(line, "No ALTQ support") &&
		   !strings.Contains(line, "ALTQ related functions disabled") &&
		   !strings.Contains(line, "pfctl:") {
			rules = append(rules, line)
		}
	}
	
	return rules, nil
}

// ClearRules removes all rules from our anchor
func (fm *FirewallManager) ClearRules() error {
	// Create empty anchor file
	if err := fm.createAnchorFile(); err != nil {
		return err
	}
	
	// Reload empty anchor
	return fm.reloadAnchor()
}

// CleanupExpiredRules removes expired rules from the firewall
func (fm *FirewallManager) CleanupExpiredRules() error {
	// Read current anchor file
	content, err := os.ReadFile(fm.anchorFile)
	if err != nil {
		return fmt.Errorf("failed to read anchor file: %v", err)
	}
	
	lines := strings.Split(string(content), "\n")
	var validLines []string
	now := time.Now()
	removedCount := 0
	
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Check if this is a rule with expiration
		if strings.Contains(line, "# CLI-Snitch-Expires:") {
			// Extract expiration time from comment
			parts := strings.Split(line, "CLI-Snitch-Expires:")
			if len(parts) == 2 {
				expiryStr := strings.TrimSpace(parts[1])
				if expiryTime, err := time.Parse(time.RFC3339, expiryStr); err == nil {
					if now.After(expiryTime) {
						// Rule has expired. The anchor format is:
						//   line i-1: # description comment
						//   line i:   # CLI-Snitch-Expires: ...
						//   line i+1: the actual pf rule
						// Remove the description comment that precedes this expiration line
						// (if it exists and is a comment, and not the file header).
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
							i++ // Skip the actual rule line too
						}
						continue
					}
				}
			}
		}

		validLines = append(validLines, line)
	}
	
	if removedCount > 0 {
		// Write back the cleaned content
		newContent := strings.Join(validLines, "\n")
		if err := os.WriteFile(fm.anchorFile, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write cleaned anchor file: %v", err)
		}
		
		// Reload the anchor
		if err := fm.reloadAnchor(); err != nil {
			return fmt.Errorf("failed to reload anchor after cleanup: %v", err)
		}
	}
	
	return nil
}

// StartStatusMonitor starts background monitoring of firewall status
func (fm *FirewallManager) StartStatusMonitor(ctx context.Context, interval time.Duration, callback func(status map[string]interface{})) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				status, err := fm.GetStatus()
				if err != nil {
					status = map[string]interface{}{
						"error": err.Error(),
						"monitoring": false,
					}
				}
				
				// Add rule count and cleanup info
				rules, err := fm.ListRules()
				if err == nil {
					status["active_rules"] = len(rules)
				}
				
				// Attempt cleanup of expired rules
				if cleanupErr := fm.CleanupExpiredRules(); cleanupErr == nil {
					status["last_cleanup"] = time.Now().Format(time.RFC3339)
				}
				
				if callback != nil {
					callback(status)
				}
			}
		}
	}()
}

// GetAnchorName returns the pfctl anchor name
func (fm *FirewallManager) GetAnchorName() string {
	return fm.anchorName
}

// GetAnchorFile returns the pfctl anchor file path
func (fm *FirewallManager) GetAnchorFile() string {
	return fm.anchorFile
}

// GetConfigFile returns the pfctl config file path
func (fm *FirewallManager) GetConfigFile() string {
	return fm.configFile
}

// GeneratePfRule converts a FirewallRule to pfctl syntax (public method)
func (fm *FirewallManager) GeneratePfRule(rule *FirewallRule) (string, error) {
	return fm.generatePfRule(rule)
}

// CheckPfctlAvailable checks if pfctl is available on the system
func (fm *FirewallManager) CheckPfctlAvailable() error {
	_, err := exec.LookPath("pfctl")
	if err != nil {
		return fmt.Errorf("pfctl not found in PATH: %w", err)
	}
	return nil
}

// LogAction writes a connection action to the firewall log file at ~/.cli-snitch/firewall.log.
func (fm *FirewallManager) LogAction(processName, host, port, action string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to determine home directory: %w", err)
	}

	logDir := filepath.Join(homeDir, ".cli-snitch")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	logFile := filepath.Join(logDir, "firewall.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	entry := fmt.Sprintf("[%s] process=%s host=%s port=%s action=%s\n",
		time.Now().Format(time.RFC3339), processName, host, port, action)

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write log entry: %w", err)
	}

	return nil
} 