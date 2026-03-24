package prompt

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"cli-snitch/monitor"
	"cli-snitch/rules"
)

var (
	// Color functions for consistent styling
	cyan     = color.New(color.FgCyan).SprintFunc()
	yellow   = color.New(color.FgYellow).SprintFunc()
	green    = color.New(color.FgGreen).SprintFunc()
	red      = color.New(color.FgRed).SprintFunc()
	blue     = color.New(color.FgBlue).SprintFunc()
	magenta  = color.New(color.FgMagenta).SprintFunc()
	bold     = color.New(color.Bold).SprintFunc()
	faint    = color.New(color.Faint).SprintFunc()

	titleCaser = cases.Title(language.English)
)

// UserDecision represents the user's choice for a connection
type UserDecision struct {
	Action      rules.Action
	Scope       rules.RuleScope
	Description string
}

// promptRequest represents a queued prompt waiting to be processed
type promptRequest struct {
	conn     *monitor.Connection
	resultCh chan promptResult
}

// promptResult carries the response back from the prompt worker
type promptResult struct {
	decision *UserDecision
	err      error
}

// ConnectionPrompter handles user interaction for connection decisions
type ConnectionPrompter struct {
	interactive bool
	promptQueue chan *promptRequest
	dnsCache    sync.Map
}

// NewConnectionPrompter creates a new connection prompter
func NewConnectionPrompter(interactive bool) *ConnectionPrompter {
	return &ConnectionPrompter{
		interactive: interactive,
		promptQueue: make(chan *promptRequest, 100),
	}
}

// QueuePrompt sends a connection to the prompt queue and waits for a response.
// This prevents stdin collisions when multiple connections arrive simultaneously.
func (cp *ConnectionPrompter) QueuePrompt(conn *monitor.Connection) (*UserDecision, error) {
	req := &promptRequest{
		conn:     conn,
		resultCh: make(chan promptResult, 1),
	}

	cp.promptQueue <- req

	res := <-req.resultCh
	return res.decision, res.err
}

// StartPromptWorker starts a goroutine that reads from the prompt queue and
// calls PromptForDecision serially, ensuring only one prompt is active at a time.
func (cp *ConnectionPrompter) StartPromptWorker(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req, ok := <-cp.promptQueue:
				if !ok {
					return
				}
				decision, err := cp.PromptForDecision(req.conn)
				req.resultCh <- promptResult{decision: decision, err: err}
			}
		}
	}()
}

// StopPromptWorker closes the prompt queue channel, causing the worker to exit.
func (cp *ConnectionPrompter) StopPromptWorker() {
	close(cp.promptQueue)
}

// PromptForDecision presents a connection to the user and gets their decision
func (cp *ConnectionPrompter) PromptForDecision(conn *monitor.Connection) (*UserDecision, error) {
	if !cp.interactive {
		// In non-interactive mode, default to allow once
		return &UserDecision{
			Action:      rules.AllowOnce,
			Scope:       rules.Exact,
			Description: "Auto-allowed in non-interactive mode",
		}, nil
	}

	// Display connection information
	cp.displayConnectionInfo(conn)

	// Get user's action choice
	action, err := cp.promptForAction()
	if err != nil {
		return nil, fmt.Errorf("failed to get action: %v", err)
	}

	// For "once" actions, use exact scope and return immediately
	if action == rules.AllowOnce || action == rules.DenyOnce {
		return &UserDecision{
			Action:      action,
			Scope:       rules.Exact,
			Description: fmt.Sprintf("%s %s connection to %s:%s",
				titleCaser.String(string(action)), conn.ProcessName, conn.RemoteAddr, conn.RemotePort),
		}, nil
	}

	// For persistent actions, get the scope
	scope, err := cp.promptForScope(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get scope: %v", err)
	}

	// Generate description
	description := cp.generateDescription(action, scope, conn)

	return &UserDecision{
		Action:      action,
		Scope:       scope,
		Description: description,
	}, nil
}

// displayConnectionInfo shows detailed connection information to the user
func (cp *ConnectionPrompter) displayConnectionInfo(conn *monitor.Connection) {
	fmt.Println()
	fmt.Println(cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Printf("%s %s\n", red("🚨"), bold("New Outbound Connection Detected"))
	fmt.Println(cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Application info
	fmt.Printf("  %s %s\n", blue("📱 Application:"), bold(conn.ProcessName))
	fmt.Printf("  %s %s\n", faint("🆔 Process ID:"), faint(fmt.Sprintf("%d", conn.PID)))
	fmt.Printf("  %s %s\n", faint("👤 User:"), faint(conn.User))
	fmt.Println()

	// Connection details
	fmt.Printf("  %s %s\n", yellow("🌐 Destination:"), bold(fmt.Sprintf("%s:%s", conn.RemoteAddr, conn.RemotePort)))
	fmt.Printf("  %s %s\n", faint("🔌 Protocol:"), faint(strings.ToUpper(conn.Protocol)))
	fmt.Printf("  %s %s\n", faint("📍 Local:"), faint(fmt.Sprintf("%s:%s", conn.LocalAddr, conn.LocalPort)))
	fmt.Println()

	// Try to resolve hostname for IP addresses
	if hostInfo := cp.getHostInfo(conn.RemoteAddr); hostInfo != "" {
		fmt.Printf("  %s %s\n", magenta("🏷️  Host Info:"), hostInfo)
		fmt.Println()
	}
}

// promptForAction asks the user what action to take
func (cp *ConnectionPrompter) promptForAction() (rules.Action, error) {
	prompt := &survey.Select{
		Message: "What would you like to do with this connection?",
		Options: []string{
			fmt.Sprintf("%s Allow Once", green("✅")),
			fmt.Sprintf("%s Allow Always", green("🔁")),
			fmt.Sprintf("%s Deny Once", red("❌")),
			fmt.Sprintf("%s Deny Always", red("🚫")),
		},
		Default: fmt.Sprintf("%s Allow Once", green("✅")),
	}

	var choice string
	err := survey.AskOne(prompt, &choice)
	if err != nil {
		return "", err
	}

	// Parse the choice
	switch {
	case strings.Contains(choice, "Allow Once"):
		return rules.AllowOnce, nil
	case strings.Contains(choice, "Allow Always"):
		return rules.Allow, nil
	case strings.Contains(choice, "Deny Once"):
		return rules.DenyOnce, nil
	case strings.Contains(choice, "Deny Always"):
		return rules.Deny, nil
	default:
		return rules.AllowOnce, nil // Default fallback
	}
}

// promptForScope asks the user how broad the rule should be
func (cp *ConnectionPrompter) promptForScope(conn *monitor.Connection) (rules.RuleScope, error) {
	fmt.Println()
	fmt.Printf("%s How broad should this rule be?\n", bold("🎯"))

	options := []string{
		fmt.Sprintf("🎯 This exact connection (%s → %s:%s)",
			conn.ProcessName, conn.RemoteAddr, conn.RemotePort),
		fmt.Sprintf("🌐 %s to any %s connections",
			conn.ProcessName, conn.RemoteAddr),
		fmt.Sprintf("🔌 %s to any :%s connections",
			conn.ProcessName, conn.RemotePort),
		fmt.Sprintf("📱 All %s connections",
			conn.ProcessName),
	}

	prompt := &survey.Select{
		Message: "Select rule scope:",
		Options: options,
		Default: options[0],
	}

	var choice string
	err := survey.AskOne(prompt, &choice)
	if err != nil {
		return "", err
	}

	// Parse the choice
	switch {
	case strings.Contains(choice, "This exact connection"):
		return rules.Exact, nil
	case strings.Contains(choice, "to any "+conn.RemoteAddr):
		return rules.ProcessAndHost, nil
	case strings.Contains(choice, "to any :"+conn.RemotePort):
		return rules.ProcessAndPort, nil
	case strings.Contains(choice, "All "+conn.ProcessName):
		return rules.ProcessOnly, nil
	default:
		return rules.Exact, nil // Default fallback
	}
}

// generateDescription creates a human-readable description for the rule
func (cp *ConnectionPrompter) generateDescription(action rules.Action, scope rules.RuleScope, conn *monitor.Connection) string {
	actionStr := titleCaser.String(string(action))

	switch scope {
	case rules.Exact:
		return fmt.Sprintf("%s %s to connect to %s:%s",
			actionStr, conn.ProcessName, conn.RemoteAddr, conn.RemotePort)
	case rules.ProcessAndHost:
		return fmt.Sprintf("%s %s to connect to %s (any port)",
			actionStr, conn.ProcessName, conn.RemoteAddr)
	case rules.ProcessAndPort:
		return fmt.Sprintf("%s %s to connect to port %s (any host)",
			actionStr, conn.ProcessName, conn.RemotePort)
	case rules.ProcessOnly:
		return fmt.Sprintf("%s all %s network connections",
			actionStr, conn.ProcessName)
	default:
		return fmt.Sprintf("%s %s connection", actionStr, conn.ProcessName)
	}
}

// getHostInfo attempts to provide additional context about the destination
func (cp *ConnectionPrompter) getHostInfo(addr string) string {
	// Check for common services by IP patterns
	if strings.HasPrefix(addr, "142.250.") || strings.HasPrefix(addr, "172.217.") ||
		strings.HasPrefix(addr, "142.251.") || strings.HasPrefix(addr, "216.58.") {
		return "Google Services"
	}

	if strings.HasPrefix(addr, "13.") || strings.HasPrefix(addr, "54.") ||
		strings.HasPrefix(addr, "18.") || strings.HasPrefix(addr, "52.") ||
		strings.HasPrefix(addr, "3.") {
		return "Amazon Web Services (AWS)"
	}

	if strings.HasPrefix(addr, "104.16.") || strings.HasPrefix(addr, "104.17.") ||
		strings.HasPrefix(addr, "104.18.") || strings.HasPrefix(addr, "172.64.") ||
		strings.HasPrefix(addr, "172.66.") {
		return "Cloudflare"
	}

	if strings.HasPrefix(addr, "185.199.") {
		return "GitHub/Microsoft"
	}

	// Check for private/local addresses
	if strings.HasPrefix(addr, "192.168.") || strings.HasPrefix(addr, "10.") ||
		strings.HasPrefix(addr, "172.16.") || strings.HasPrefix(addr, "172.17.") ||
		strings.HasPrefix(addr, "172.18.") || strings.HasPrefix(addr, "172.19.") ||
		strings.HasPrefix(addr, "172.20.") || strings.HasPrefix(addr, "172.21.") ||
		strings.HasPrefix(addr, "172.22.") || strings.HasPrefix(addr, "172.23.") ||
		strings.HasPrefix(addr, "172.24.") || strings.HasPrefix(addr, "172.25.") ||
		strings.HasPrefix(addr, "172.26.") || strings.HasPrefix(addr, "172.27.") ||
		strings.HasPrefix(addr, "172.28.") || strings.HasPrefix(addr, "172.29.") ||
		strings.HasPrefix(addr, "172.30.") || strings.HasPrefix(addr, "172.31.") {
		return "Local Network"
	}

	// Check DNS cache first
	if cached, ok := cp.dnsCache.Load(addr); ok {
		return cached.(string)
	}

	// Try reverse DNS lookup with a 500ms timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			return d.DialContext(ctx, network, address)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		hostname := strings.TrimSuffix(names[0], ".")
		cp.dnsCache.Store(addr, hostname)
		return hostname
	}

	// Cache empty result to avoid repeated lookups
	cp.dnsCache.Store(addr, "")
	return ""
}

// DisplayRuleSummary shows a summary of the rule that was created
func (cp *ConnectionPrompter) DisplayRuleSummary(decision *UserDecision, rule *rules.Rule) {
	fmt.Println()
	fmt.Println(cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

	var statusIcon string
	var statusColor func(...interface{}) string
	if decision.Action == rules.Allow || decision.Action == rules.AllowOnce {
		statusIcon = green("✅")
		statusColor = green
	} else {
		statusIcon = red("❌")
		statusColor = red
	}

	fmt.Printf("%s %s\n", statusIcon, bold(statusColor("Rule Created")))
	fmt.Println(cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Printf("  %s %s\n", blue("📋 Description:"), decision.Description)
	if rule != nil {
		fmt.Printf("  %s %s\n", faint("🆔 Rule ID:"), faint(rule.ID))
	}
	fmt.Println()
}

// ConfirmBulkAction asks for confirmation before applying rules to many connections
func (cp *ConnectionPrompter) ConfirmBulkAction(count int, processName string) (bool, error) {
	if count <= 1 {
		return true, nil // No confirmation needed for single connections
	}

	fmt.Println()
	fmt.Printf("%s Found %d similar %s connections. Apply the same rule to all of them?\n",
		yellow("⚠️"), count, processName)

	confirm := false
	prompt := &survey.Confirm{
		Message: "Apply to all similar connections?",
		Default: true,
	}

	err := survey.AskOne(prompt, &confirm)
	return confirm, err
}
