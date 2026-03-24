package main

import (
	"fmt"
	"os"

	"cli-snitch/monitor"

	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show connection history",
	Long:  `Display recent connection decisions from the history log.`,
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		filterProcess, _ := cmd.Flags().GetString("process")
		filterAction, _ := cmd.Flags().GetString("action")

		history := monitor.NewConnectionHistoryWithPath(getHistoryFile())
		entries, err := history.GetHistory(limit)
		if err != nil {
			fmt.Printf("%s Failed to read history: %v\n", red("❌"), err)
			os.Exit(1)
		}

		if len(entries) == 0 {
			fmt.Printf("%s No connection history found.\n", yellow("📝"))
			fmt.Println("History is recorded when using 'cli-snitch watch'.")
			return
		}

		// Apply filters
		var filtered []monitor.HistoryEntry
		for _, entry := range entries {
			if filterProcess != "" && entry.ProcessName != filterProcess {
				continue
			}
			if filterAction != "" && entry.Action != filterAction {
				continue
			}
			filtered = append(filtered, entry)
		}

		if len(filtered) == 0 {
			fmt.Printf("%s No matching history entries.\n", yellow("📝"))
			return
		}

		fmt.Printf("%s Connection History (%d entries):\n\n", cyan("📜"), len(filtered))

		for _, entry := range filtered {
			actionColor := green
			actionIcon := "✅"
			if entry.Action == "denied" {
				actionColor = red
				actionIcon = "❌"
			}

			fmt.Printf("%s %s %s %s -> %s:%s\n",
				faint(entry.Timestamp.Format("2006-01-02 15:04:05")),
				actionColor(actionIcon),
				cyan(entry.ProcessName),
				actionColor(entry.Action),
				entry.RemoteAddr,
				entry.RemotePort)
		}
	},
}

func init() {
	historyCmd.Flags().IntP("limit", "n", 50, "Number of entries to show")
	historyCmd.Flags().StringP("process", "p", "", "Filter by process name")
	historyCmd.Flags().StringP("action", "a", "", "Filter by action (allowed/denied)")
}
