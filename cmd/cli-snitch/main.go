package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/fatih/color"
	"cli-snitch/monitor"
	"cli-snitch/rules"
	"cli-snitch/prompt"
)

var (
	green = color.New(color.FgGreen).SprintFunc()
	red   = color.New(color.FgRed).SprintFunc()
	cyan  = color.New(color.FgCyan).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	faint = color.New(color.Faint).SprintFunc()
)

var rootCmd = &cobra.Command{
	Use:   "cli-snitch",
	Short: "A Little Snitch clone for macOS terminal",
	Long: `CLI Snitch is a terminal-based network monitoring tool that replicates 
core Little Snitch features for macOS. It monitors outgoing connections, 
prompts for user decisions, and manages firewall rules.`,
}

var watchCmd = &cobra.Command{
	Use:   "watch", 
	Short: "Start monitoring network connections",
	Long:  `Start the real-time network connection monitoring daemon`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(cyan("🔍 CLI Snitch - Network Monitor"))
		fmt.Println("Press Ctrl+C to stop monitoring...")
		
		// Check if running as root
		if os.Geteuid() != 0 {
			fmt.Println(red("❌ Error: CLI Snitch requires sudo privileges"))
			fmt.Println(yellow("   Please run: sudo cli-snitch watch"))
			os.Exit(1)
		}
		
		fmt.Println(green("✅ Starting network monitoring..."))
		
		// Set up signal handling for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		
		// Initialize rule manager and prompter
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("%s Failed to get home directory: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		rulesFile := filepath.Join(homeDir, ".cli-snitch", "rules.json")
		ruleManager := rules.NewRuleManager(rulesFile)
		
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		connectionPrompter := prompt.NewConnectionPrompter(true) // Interactive mode
		
		fmt.Printf("%s Loaded %d existing rules from %s\n", 
			green("📋"), len(ruleManager.GetAllRules()), rulesFile)
		
		// Create connection monitor with decision handling callback
		connectionMonitor := monitor.NewConnectionMonitor(func(conn *monitor.Connection) {
			handleNewConnection(conn, ruleManager, connectionPrompter)
		})
		
		// Create context for graceful shutdown
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		
		// Start monitoring in a goroutine
		monitorErr := make(chan error, 1)
		go func() {
			fmt.Println(yellow("📡 Starting continuous network monitoring..."))
			err := connectionMonitor.StartMonitoring(ctx, 2 * time.Second) // Check every 2 seconds
			if err != nil && err != context.Canceled {
				monitorErr <- err
			}
		}()
		
		// Wait for shutdown signal or monitor error
		select {
		case <-sigChan:
			fmt.Println(yellow("\n📴 Shutting down CLI Snitch..."))
			cancel() // Signal monitor to stop
		case err := <-monitorErr:
			fmt.Printf("%s Monitor error: %v\n", red("❌"), err)
			cancel() // Signal monitor to stop
		}
		
		fmt.Println(green("✅ Cleanup complete. Goodbye!"))
	},
}

// handleNewConnection processes a new connection through the decision pipeline
func handleNewConnection(conn *monitor.Connection, ruleManager *rules.RuleManager, prompter *prompt.ConnectionPrompter) {
	// Create connection info for rule matching
	connInfo := rules.ConnectionInfo{
		ProcessName: conn.ProcessName,
		Host:        conn.RemoteAddr,
		Port:        conn.RemotePort,
	}
	
	// Check if we have an existing rule
	if existingRule, found := ruleManager.FindMatchingRule(connInfo); found {
		// Rule found - apply it
		switch existingRule.Action {
		case rules.Allow, rules.AllowOnce:
			fmt.Printf("%s %s %s -> %s:%s [%s]\n",
				green("✅"),
				cyan(conn.ProcessName),
				green("ALLOWED"),
				conn.RemoteAddr,
				conn.RemotePort,
				faint(existingRule.Description))
			// Note: In a full implementation, we'd allow the connection here
			
		case rules.Deny, rules.DenyOnce:
			fmt.Printf("%s %s %s -> %s:%s [%s]\n",
				red("❌"),
				cyan(conn.ProcessName),
				red("DENIED"),
				conn.RemoteAddr,
				conn.RemotePort,
				faint(existingRule.Description))
			// Note: In a full implementation, we'd block the connection here
		}
		
		// Remove "once" rules after use
		if existingRule.Action == rules.AllowOnce || existingRule.Action == rules.DenyOnce {
			ruleManager.DeleteRule(existingRule.ID)
		}
		
		return
	}
	
	// No rule found - prompt user for decision
	fmt.Printf("%s %s New connection detected: %s -> %s:%s\n",
		yellow("🔍"),
		cyan(conn.ProcessName),
		conn.RemoteAddr,
		conn.RemotePort,
		faint("(awaiting decision)"))
	
	decision, err := prompter.PromptForDecision(conn)
	if err != nil {
		fmt.Printf("%s Failed to get user decision: %v\n", red("❌"), err)
		// Default to allow once on error
		decision = &prompt.UserDecision{
			Action:      rules.AllowOnce,
			Scope:       rules.Exact,
			Description: "Auto-allowed due to prompt error",
		}
	}
	
	// Apply the decision immediately
	switch decision.Action {
	case rules.Allow, rules.AllowOnce:
		fmt.Printf("%s %s %s -> %s:%s\n",
			green("✅"),
			cyan(conn.ProcessName),
			green("ALLOWED"),
			conn.RemoteAddr,
			conn.RemotePort)
		// Note: In a full implementation, we'd allow the connection here
		
	case rules.Deny, rules.DenyOnce:
		fmt.Printf("%s %s %s -> %s:%s\n",
			red("❌"),
			cyan(conn.ProcessName),
			red("DENIED"),
			conn.RemoteAddr,
			conn.RemotePort)
		// Note: In a full implementation, we'd block the connection here
	}
	
	// Create and save rule for persistent actions
	if decision.Action == rules.Allow || decision.Action == rules.Deny {
		rule := rules.Rule{
			ProcessName: conn.ProcessName,
			Action:      decision.Action,
			Scope:       decision.Scope,
			Description: decision.Description,
		}
		
		// Set host and port based on scope
		switch decision.Scope {
		case rules.ProcessAndHost:
			rule.Host = conn.RemoteAddr
		case rules.ProcessAndPort:
			rule.Port = conn.RemotePort
		case rules.Exact:
			rule.Host = conn.RemoteAddr
			rule.Port = conn.RemotePort
		}
		
		if err := ruleManager.AddRule(rule); err != nil {
			fmt.Printf("%s Failed to save rule: %v\n", red("❌"), err)
		} else {
			prompter.DisplayRuleSummary(decision, &rule)
		}
	}
}

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all saved rules",
	Long:  `Display all saved allow/deny rules in a formatted table`,
	Run: func(cmd *cobra.Command, args []string) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("%s Failed to get home directory: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		rulesFile := filepath.Join(homeDir, ".cli-snitch", "rules.json")
		ruleManager := rules.NewRuleManager(rulesFile)
		
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		allRules := ruleManager.GetAllRules()
		if len(allRules) == 0 {
			fmt.Printf("%s No rules found.\n", yellow("📝"))
			return
		}
		
		fmt.Printf("%s Found %d rules:\n\n", green("📋"), len(allRules))
		
		for _, rule := range allRules {
			actionColor := green
			if rule.Action == rules.Deny {
				actionColor = red
			}
			
			fmt.Printf("%s %s %s\n", 
				actionColor(string(rule.Action)), 
				cyan(rule.ProcessName),
				rule.Description)
			
			if rule.Host != "" {
				fmt.Printf("    Host: %s\n", rule.Host)
			}
			if rule.Port != "" {
				fmt.Printf("    Port: %s\n", rule.Port)
			}
			fmt.Printf("    Scope: %s\n", rule.Scope)
			fmt.Printf("    Created: %s\n", rule.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}
	},
}

var clearRulesCmd = &cobra.Command{
	Use:   "clear-rules",
	Short: "Clear all saved rules",
	Long:  `Remove all saved allow/deny rules (requires confirmation)`,
	Run: func(cmd *cobra.Command, args []string) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("%s Failed to get home directory: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		rulesFile := filepath.Join(homeDir, ".cli-snitch", "rules.json")
		ruleManager := rules.NewRuleManager(rulesFile)
		
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		allRules := ruleManager.GetAllRules()
		if len(allRules) == 0 {
			fmt.Printf("%s No rules to clear.\n", yellow("📝"))
			return
		}
		
		fmt.Printf("%s This will delete all %d rules. Are you sure? (y/N): ", 
			yellow("⚠️"), len(allRules))
		
		var response string
		fmt.Scanln(&response)
		
		if response != "y" && response != "Y" {
			fmt.Printf("%s Operation cancelled.\n", yellow("❌"))
			return
		}
		
		if err := ruleManager.ClearRules(); err != nil {
			fmt.Printf("%s Failed to clear rules: %v\n", red("❌"), err)
			os.Exit(1)
		}
		
		fmt.Printf("%s All rules cleared successfully.\n", green("✅"))
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(listRulesCmd)
	rootCmd.AddCommand(clearRulesCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
} 