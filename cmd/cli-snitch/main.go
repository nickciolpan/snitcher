package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	faint  = color.New(color.Faint).SprintFunc()
)

var rootCmd = &cobra.Command{
	Use:   "cli-snitch",
	Short: "A Little Snitch clone for macOS terminal",
	Long: `CLI Snitch is a terminal-based network monitoring tool that replicates
core Little Snitch features for macOS. It monitors outgoing connections,
prompts for user decisions, and manages firewall rules.`,
}

func init() {
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(listRulesCmd)
	rootCmd.AddCommand(clearRulesCmd)
	rootCmd.AddCommand(editRuleCmd)
	rootCmd.AddCommand(importRulesCmd)
	rootCmd.AddCommand(exportRulesCmd)
	rootCmd.AddCommand(firewallStatusCmd)
	rootCmd.AddCommand(clearFirewallCmd)
	rootCmd.AddCommand(listFirewallCmd)
	rootCmd.AddCommand(firewallCleanupCmd)
	rootCmd.AddCommand(firewallMonitorCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(systemStatusCmd)
	rootCmd.AddCommand(daemonCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
