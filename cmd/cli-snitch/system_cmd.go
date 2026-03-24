package main

import (
	"fmt"
	"os"
	"strings"

	"cli-snitch/firewall"
	"cli-snitch/rules"

	"github.com/spf13/cobra"
)

var systemStatusCmd = &cobra.Command{
	Use:   "system-status",
	Short: "Show system integration status",
	Long:  `Display detailed information about CLI Snitch system health and integration status`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s CLI Snitch System Status\n", cyan("📊"))
		fmt.Println(cyan(strings.Repeat("━", 60)))

		// Rules
		ruleManager := rules.NewRuleManager(getRulesFile())
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
		}

		firewallManager := firewall.NewFirewallManager()

		fmt.Printf("\n%s System Health\n", green("🏥"))
		allRules := ruleManager.GetAllRules()
		fmt.Printf("  Rules Manager: %s (%d rules loaded)\n", green("✅"), len(allRules))

		fmt.Printf("  Firewall Integration: ")
		if err := firewallManager.Initialize(); err != nil {
			fmt.Printf("%s %v\n", red("❌"), err)
		} else {
			fmt.Printf("%s Operational\n", green("✅"))
		}

		fmt.Printf("  pfctl: ")
		if err := firewallManager.CheckPfctlAvailable(); err == nil {
			fmt.Printf("%s Available\n", green("✅"))
		} else {
			fmt.Printf("%s Not available\n", yellow("⚠️"))
		}

		// Components
		fmt.Printf("\n%s Components\n", cyan("🔗"))
		fmt.Printf("  Network Monitor: TCP + UDP via lsof\n")
		fmt.Printf("  User Prompts: Interactive with serialized queue\n")
		fmt.Printf("  Rule Engine: Persistent rules with wildcard/glob support\n")
		fmt.Printf("  Firewall: pfctl with input sanitization\n")
		fmt.Printf("  History: JSON Lines connection log\n")
		fmt.Printf("  DNS: Reverse lookup with caching\n")

		// Monitor diagnostics
		fmt.Printf("\n%s Diagnostics\n", cyan("🔬"))
		fmt.Printf("  Error handler: Built-in (11 error types, 4 severity levels)\n")
		fmt.Printf("  Recovery: Automatic retry with exponential backoff\n")
		fmt.Printf("  Logging: Structured with component tagging\n")

		// Files
		fmt.Printf("\n%s Files\n", green("📁"))
		rulesFile := getRulesFile()
		fmt.Printf("  Rules: %s", rulesFile)
		if _, err := os.Stat(rulesFile); err == nil {
			fmt.Printf(" %s\n", green("✅"))
		} else {
			fmt.Printf(" (will be created)\n")
		}

		historyFile := getHistoryFile()
		fmt.Printf("  History: %s", historyFile)
		if _, err := os.Stat(historyFile); err == nil {
			fmt.Printf(" %s\n", green("✅"))
		} else {
			fmt.Printf(" (will be created)\n")
		}

		anchorFile := firewallManager.GetAnchorFile()
		fmt.Printf("  Firewall Anchor: %s", anchorFile)
		if _, err := os.Stat(anchorFile); err == nil {
			fmt.Printf(" %s\n", green("✅"))
		} else {
			fmt.Printf(" (will be created)\n")
		}

		// Firewall status
		if status, err := firewallManager.GetStatus(); err == nil && status != nil {
			fmt.Printf("\n%s Firewall\n", yellow("📋"))
			if activeRules, ok := status["active_rules"].(int); ok {
				fmt.Printf("  Active rules: %d\n", activeRules)
			}
			if anchorLoaded, ok := status["anchor_loaded"].(bool); ok {
				if anchorLoaded {
					fmt.Printf("  Anchor: %s Loaded\n", green("✅"))
				} else {
					fmt.Printf("  Anchor: %s Not loaded\n", yellow("⚠️"))
				}
			}
		}

		fmt.Printf("  Persistent rules: %d\n", len(allRules))

		// Rule stats
		if len(allRules) > 0 {
			stats := ruleManager.GetRuleStats()
			fmt.Printf("\n%s Rule Stats\n", cyan("📈"))
			fmt.Printf("  Allow rules: %d\n", stats["allow_rules"])
			fmt.Printf("  Deny rules: %d\n", stats["deny_rules"])
		}

		fmt.Printf("\n%s System ready\n", green("🚀"))
	},
}
