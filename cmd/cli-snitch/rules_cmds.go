package main

import (
	"fmt"
	"os"
	"strings"

	"cli-snitch/rules"

	"github.com/spf13/cobra"
)

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all saved rules",
	Long:  `Display all saved allow/deny rules in a formatted table`,
	Run: func(cmd *cobra.Command, args []string) {
		ruleManager := rules.NewRuleManager(getRulesFile())
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
			if rule.Pattern != "" {
				fmt.Printf("    Pattern: %s\n", rule.Pattern)
			}
			fmt.Printf("    Scope: %s | ID: %s\n", rule.Scope, rule.ID)
			fmt.Printf("    Created: %s | Used: %d times\n", rule.CreatedAt.Format("2006-01-02 15:04:05"), rule.UseCount)
			fmt.Println()
		}
	},
}

var clearRulesCmd = &cobra.Command{
	Use:   "clear-rules",
	Short: "Clear all saved rules",
	Long:  `Remove all saved allow/deny rules (requires confirmation)`,
	Run: func(cmd *cobra.Command, args []string) {
		ruleManager := rules.NewRuleManager(getRulesFile())
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

		fmt.Printf("%s All rules cleared.\n", green("✅"))
	},
}

var editRuleCmd = &cobra.Command{
	Use:   "edit-rule [rule-id]",
	Short: "Edit an existing rule",
	Long:  `Modify an existing rule's action, scope, or description`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ruleID := args[0]

		ruleManager := rules.NewRuleManager(getRulesFile())
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
			os.Exit(1)
		}

		// Find the rule
		allRules := ruleManager.GetAllRules()
		var found *rules.Rule
		for _, r := range allRules {
			if r.ID == ruleID {
				found = &r
				break
			}
		}

		if found == nil {
			fmt.Printf("%s Rule '%s' not found.\n", red("❌"), ruleID)
			fmt.Println("Use 'cli-snitch list-rules' to see all rule IDs.")
			os.Exit(1)
		}

		fmt.Printf("%s Editing rule: %s\n", cyan("📝"), found.Description)
		fmt.Printf("  Process: %s | Action: %s | Scope: %s\n\n",
			found.ProcessName, found.Action, found.Scope)

		// Get new action
		newAction, _ := cmd.Flags().GetString("action")
		newDescription, _ := cmd.Flags().GetString("description")
		newHost, _ := cmd.Flags().GetString("host")
		newPort, _ := cmd.Flags().GetString("port")
		newPattern, _ := cmd.Flags().GetString("pattern")

		updates := rules.Rule{}
		changed := false

		if newAction != "" {
			switch strings.ToLower(newAction) {
			case "allow":
				updates.Action = rules.Allow
				changed = true
			case "deny":
				updates.Action = rules.Deny
				changed = true
			default:
				fmt.Printf("%s Invalid action: %s (use 'allow' or 'deny')\n", red("❌"), newAction)
				os.Exit(1)
			}
		}

		if newDescription != "" {
			updates.Description = newDescription
			changed = true
		}
		if newHost != "" {
			updates.Host = newHost
			changed = true
		}
		if newPort != "" {
			updates.Port = newPort
			changed = true
		}
		if newPattern != "" {
			updates.Pattern = newPattern
			changed = true
		}

		if !changed {
			fmt.Printf("%s No changes specified. Use flags: --action, --description, --host, --port, --pattern\n", yellow("⚠️"))
			return
		}

		if err := ruleManager.UpdateRule(ruleID, updates); err != nil {
			fmt.Printf("%s Failed to update rule: %v\n", red("❌"), err)
			os.Exit(1)
		}

		fmt.Printf("%s Rule updated successfully.\n", green("✅"))
	},
}

var importRulesCmd = &cobra.Command{
	Use:   "import-rules [file]",
	Short: "Import rules from a JSON file",
	Long:  `Import rules from an exported JSON file. Use --merge to add to existing rules.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		merge, _ := cmd.Flags().GetBool("merge")

		ruleManager := rules.NewRuleManager(getRulesFile())
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
			os.Exit(1)
		}

		f, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("%s Failed to open file: %v\n", red("❌"), err)
			os.Exit(1)
		}
		defer f.Close()

		beforeCount := len(ruleManager.GetAllRules())

		if err := ruleManager.ImportRules(f, merge); err != nil {
			fmt.Printf("%s Failed to import rules: %v\n", red("❌"), err)
			os.Exit(1)
		}

		afterCount := len(ruleManager.GetAllRules())
		if merge {
			fmt.Printf("%s Imported %d rules (merged with %d existing)\n",
				green("✅"), afterCount-beforeCount, beforeCount)
		} else {
			fmt.Printf("%s Imported %d rules (replaced %d existing)\n",
				green("✅"), afterCount, beforeCount)
		}
	},
}

var exportRulesCmd = &cobra.Command{
	Use:   "export-rules [file]",
	Short: "Export rules to a JSON file",
	Long:  `Export all rules to a JSON file for backup or sharing.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		ruleManager := rules.NewRuleManager(getRulesFile())
		if err := ruleManager.LoadRules(); err != nil {
			fmt.Printf("%s Failed to load rules: %v\n", red("❌"), err)
			os.Exit(1)
		}

		allRules := ruleManager.GetAllRules()
		if len(allRules) == 0 {
			fmt.Printf("%s No rules to export.\n", yellow("📝"))
			return
		}

		f, err := os.Create(filePath)
		if err != nil {
			fmt.Printf("%s Failed to create file: %v\n", red("❌"), err)
			os.Exit(1)
		}
		defer f.Close()

		if err := ruleManager.ExportRules(f); err != nil {
			fmt.Printf("%s Failed to export rules: %v\n", red("❌"), err)
			os.Exit(1)
		}

		fmt.Printf("%s Exported %d rules to %s\n", green("✅"), len(allRules), filePath)
	},
}

func init() {
	editRuleCmd.Flags().String("action", "", "New action (allow/deny)")
	editRuleCmd.Flags().String("description", "", "New description")
	editRuleCmd.Flags().String("host", "", "New host")
	editRuleCmd.Flags().String("port", "", "New port")
	editRuleCmd.Flags().String("pattern", "", "New host pattern (e.g. *.google.com)")

	importRulesCmd.Flags().Bool("merge", false, "Merge with existing rules instead of replacing")
}
