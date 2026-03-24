package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cli-snitch/firewall"
	"cli-snitch/prompt"
	"cli-snitch/rules"

	"github.com/spf13/cobra"
)

var firewallStatusCmd = &cobra.Command{
	Use:   "firewall-status",
	Short: "Show firewall integration status",
	Long:  `Display the current status of pfctl firewall integration`,
	Run: func(cmd *cobra.Command, args []string) {
		firewallManager := firewall.NewFirewallManager()

		fmt.Printf("%s CLI Snitch Firewall Integration Status\n", cyan("🔥"))
		fmt.Println("=" + strings.Repeat("=", 49))

		fmt.Printf("Anchor Name: %s\n", firewallManager.GetAnchorName())
		fmt.Printf("Anchor File: %s\n", firewallManager.GetAnchorFile())
		fmt.Printf("Config File: %s\n", firewallManager.GetConfigFile())

		if err := firewallManager.CheckPfctlAvailable(); err != nil {
			fmt.Printf("%s pfctl not available: %v\n", red("❌"), err)
		} else {
			fmt.Printf("%s pfctl is available and ready\n", green("✅"))
		}

		fmt.Printf("\n%s Example firewall rules:\n", cyan("📋"))

		examples := []struct {
			scope       rules.RuleScope
			process     string
			host        string
			port        string
			description string
		}{
			{rules.Exact, "suspicious-app", "malicious.com", "443", "Block specific connection"},
			{rules.ProcessAndHost, "browser", "ads.tracker.com", "", "Block all to host"},
			{rules.ProcessAndPort, "game", "", "80", "Block HTTP from process"},
			{rules.ProcessOnly, "untrusted", "", "", "Block all from process"},
		}

		for i, ex := range examples {
			decision := &prompt.UserDecision{
				Action:      rules.Deny,
				Scope:       ex.scope,
				Description: ex.description,
			}
			firewallRule := firewallManager.CreateBlockRuleFromUserDecision(decision, ex.process, ex.host, ex.port)
			if firewallRule != nil {
				pfRule, err := firewallManager.GeneratePfRule(firewallRule)
				if err == nil {
					fmt.Printf("%d. %s\n", i+1, pfRule)
				}
			}
		}

		fmt.Printf("\n%s These rules are applied when deny decisions are made\n", faint("ℹ️"))
	},
}

var clearFirewallCmd = &cobra.Command{
	Use:   "clear-firewall",
	Short: "Clear all firewall rules",
	Long:  `Remove all CLI Snitch firewall rules from pfctl.`,
	Run: func(cmd *cobra.Command, args []string) {
		firewallManager := firewall.NewFirewallManager()

		fmt.Printf("%s Clearing CLI Snitch firewall rules...\n", yellow("🧹"))

		if err := firewallManager.ClearRules(); err != nil {
			fmt.Printf("%s Failed to clear: %v\n", red("❌"), err)
			os.Exit(1)
		}

		fmt.Printf("%s All CLI Snitch firewall rules cleared\n", green("✅"))
	},
}

var listFirewallCmd = &cobra.Command{
	Use:   "list-firewall",
	Short: "List active firewall rules",
	Long:  `Display all currently active CLI Snitch firewall rules in pfctl.`,
	Run: func(cmd *cobra.Command, args []string) {
		firewallManager := firewall.NewFirewallManager()

		fmt.Printf("%s Active CLI Snitch Firewall Rules\n", cyan("🔥"))
		fmt.Println("=" + strings.Repeat("=", 49))

		fwRules, err := firewallManager.ListRules()
		if err != nil {
			fmt.Printf("%s Failed to list: %v\n", red("❌"), err)
			os.Exit(1)
		}

		if len(fwRules) == 0 {
			fmt.Printf("%s No active firewall rules\n", yellow("📝"))
			return
		}

		fmt.Printf("%s Found %d active rules:\n\n", green("📋"), len(fwRules))
		for i, rule := range fwRules {
			fmt.Printf("%d. %s\n", i+1, rule)
		}

		fmt.Printf("\n%s Use 'clear-firewall' to remove all rules\n", faint("💡"))
	},
}

var firewallCleanupCmd = &cobra.Command{
	Use:   "firewall-cleanup",
	Short: "Clean up expired firewall rules",
	Long:  `Remove expired firewall rules and show cleanup summary.`,
	Run: func(cmd *cobra.Command, args []string) {
		firewallManager := firewall.NewFirewallManager()

		fmt.Printf("%s Cleaning up expired firewall rules...\n", cyan("🧹"))

		rulesBefore, err := firewallManager.ListRules()
		if err != nil {
			fmt.Printf("%s Failed to list rules: %v\n", red("❌"), err)
		}

		if err := firewallManager.CleanupExpiredRules(); err != nil {
			fmt.Printf("%s Cleanup failed: %v\n", red("❌"), err)
			os.Exit(1)
		}

		rulesAfter, err := firewallManager.ListRules()
		if err != nil {
			fmt.Printf("%s Failed to list rules: %v\n", red("❌"), err)
		}

		removed := len(rulesBefore) - len(rulesAfter)
		if removed > 0 {
			fmt.Printf("%s Removed %d expired rules\n", green("✅"), removed)
		} else {
			fmt.Printf("%s No expired rules found\n", green("✅"))
		}
		fmt.Printf("%s Current active rules: %d\n", cyan("📊"), len(rulesAfter))
	},
}

var firewallMonitorCmd = &cobra.Command{
	Use:   "firewall-monitor",
	Short: "Monitor firewall status in real-time",
	Long:  `Start real-time monitoring of firewall status and rule count.`,
	Run: func(cmd *cobra.Command, args []string) {
		firewallManager := firewall.NewFirewallManager()

		fmt.Printf("%s Starting firewall monitoring (Ctrl+C to stop)\n", cyan("🔍"))
		fmt.Println("=" + strings.Repeat("=", 49))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		firewallManager.StartStatusMonitor(ctx, 5*time.Second, func(status map[string]interface{}) {
			timestamp := time.Now().Format("15:04:05")

			if enabled, ok := status["enabled"].(bool); ok {
				enabledStr := "Disabled"
				if enabled {
					enabledStr = "Enabled"
				}
				activeRules := 0
				if r, ok := status["active_rules"].(int); ok {
					activeRules = r
				}
				fmt.Printf("[%s] pfctl: %s | Active Rules: %d\n", timestamp, enabledStr, activeRules)
			}

			if errMsg, ok := status["error"].(string); ok {
				fmt.Printf("[%s] Error: %s\n", timestamp, errMsg)
			}
		})

		<-sigChan
		fmt.Printf("\n%s Stopping firewall monitoring...\n", yellow("📴"))
	},
}
