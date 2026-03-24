package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cli-snitch/firewall"
	"cli-snitch/monitor"
	"cli-snitch/prompt"
	"cli-snitch/rules"

	"github.com/spf13/cobra"
)

// SystemStats tracks integration metrics with atomic fields for safe concurrent access
type SystemStats struct {
	StartTime           time.Time
	ConnectionsDetected int64
	RulesApplied        int64
	FirewallRulesActive int64
}

func (s *SystemStats) incrConnections() {
	atomic.AddInt64(&s.ConnectionsDetected, 1)
}

func (s *SystemStats) incrRules() {
	atomic.AddInt64(&s.RulesApplied, 1)
}

func (s *SystemStats) setFirewallRules(n int64) {
	atomic.StoreInt64(&s.FirewallRulesActive, n)
}

func (s *SystemStats) getConnections() int64 {
	return atomic.LoadInt64(&s.ConnectionsDetected)
}

func (s *SystemStats) getRules() int64 {
	return atomic.LoadInt64(&s.RulesApplied)
}

func (s *SystemStats) getFirewallRules() int64 {
	return atomic.LoadInt64(&s.FirewallRulesActive)
}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start monitoring network connections",
	Long:  `Start the real-time network connection monitoring daemon`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(cyan("🔍 CLI Snitch - Network Monitor"))
		fmt.Println("Press Ctrl+C to stop monitoring...")

		if os.Geteuid() != 0 {
			fmt.Println(red("❌ Error: CLI Snitch requires sudo privileges"))
			fmt.Println(yellow("   Please run: sudo cli-snitch watch"))
			os.Exit(1)
		}

		fmt.Println(green("✅ Starting network monitoring..."))

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

		connectionPrompter := prompt.NewConnectionPrompter(true)
		firewallManager := firewall.NewFirewallManager()

		// Initialize connection history
		historyFile := filepath.Join(homeDir, ".cli-snitch", "history.jsonl")
		connHistory := monitor.NewConnectionHistoryWithPath(historyFile)

		// Start prompt worker for serialized interactive prompts
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		connectionPrompter.StartPromptWorker(ctx)

		// Initialize firewall
		fmt.Printf("%s Initializing firewall integration...\n", cyan("🔥"))
		if err := firewallManager.Initialize(); err != nil {
			fmt.Printf("%s Failed to initialize firewall: %v\n", red("❌"), err)
			fmt.Printf("%s Continuing in monitoring-only mode\n", yellow("⚠️"))
		} else {
			fmt.Printf("%s Firewall integration ready\n", green("✅"))
		}

		fmt.Printf("%s Loaded %d existing rules from %s\n",
			green("📋"), len(ruleManager.GetAllRules()), rulesFile)

		systemStats := &SystemStats{
			StartTime: time.Now(),
		}

		// Mutex to serialize connection handling (prompt is serialized via queue,
		// but rule/firewall ops also need protection)
		var handleMu sync.Mutex

		// Monitor uses internal logger and error handler for structured diagnostics
		connectionMonitor := monitor.NewConnectionMonitor(func(conn *monitor.Connection) {
			systemStats.incrConnections()
			handleMu.Lock()
			defer handleMu.Unlock()
			handleNewConnection(conn, ruleManager, connectionPrompter, firewallManager, connHistory, systemStats)
		})

		// Firewall status monitoring
		firewallManager.StartStatusMonitor(ctx, 30*time.Second, func(status map[string]interface{}) {
			if activeRules, ok := status["active_rules"].(int); ok {
				systemStats.setFirewallRules(int64(activeRules))
				if activeRules > 0 {
					fmt.Printf("%s Firewall: %d active rules | %d connections | %s uptime\n",
						faint("🛡️"), activeRules, systemStats.getConnections(),
						faint(time.Since(systemStats.StartTime).Round(time.Second).String()))
				}
			}
		})

		// Periodic maintenance
		go func() {
			cleanupTicker := time.NewTicker(5 * time.Minute)
			flushTicker := time.NewTicker(30 * time.Second)
			defer cleanupTicker.Stop()
			defer flushTicker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-cleanupTicker.C:
					if err := firewallManager.CleanupExpiredRules(); err != nil {
						fmt.Printf("%s Cleanup warning: %v\n", yellow("⚠️"), err)
					}
					if err := ruleManager.SaveRules(); err != nil {
						fmt.Printf("%s Failed to save rules: %v\n", yellow("⚠️"), err)
					}
					fmt.Printf("%s Maintenance completed\n", faint("🧹"))
				case <-flushTicker.C:
					// Periodically flush rule usage stats
					if err := ruleManager.FlushIfDirty(); err != nil {
						fmt.Printf("%s Failed to flush rules: %v\n", yellow("⚠️"), err)
					}
				}
			}
		}()

		// Start monitoring with retry
		monitorErr := make(chan error, 1)
		go func() {
			fmt.Println(yellow("📡 Starting continuous network monitoring..."))
			retryCount := 0
			maxRetries := 3

			for retryCount <= maxRetries {
				err := connectionMonitor.StartMonitoring(ctx, 2*time.Second)
				if err == context.Canceled {
					return
				}
				if err != nil {
					retryCount++
					if retryCount <= maxRetries {
						fmt.Printf("%s Monitor error (attempt %d/%d): %v - retrying...\n",
							yellow("⚠️"), retryCount, maxRetries, err)
						time.Sleep(5 * time.Second)
						continue
					}
					monitorErr <- fmt.Errorf("monitor failed after %d attempts: %v", maxRetries, err)
					return
				}
			}
		}()

		fmt.Printf("%s System ready for network monitoring.\n", green("✅"))
		fmt.Printf("%s Press Ctrl+C to stop...\n", faint("ℹ️"))

		select {
		case <-sigChan:
			fmt.Println(yellow("\n📴 Shutting down CLI Snitch..."))
			cancel()
			time.Sleep(2 * time.Second)
		case err := <-monitorErr:
			fmt.Printf("%s Critical error: %v\n", red("❌"), err)
			cancel()
		}

		// Shutdown stats
		fmt.Printf("%s Final statistics...\n", cyan("📊"))
		fmt.Printf("  Uptime: %s\n", time.Since(systemStats.StartTime).Round(time.Second))
		fmt.Printf("  Connections processed: %d\n", systemStats.getConnections())
		fmt.Printf("  Rules applied: %d\n", systemStats.getRules())
		fmt.Printf("  Active firewall rules: %d\n", systemStats.getFirewallRules())

		if err := firewallManager.CleanupExpiredRules(); err != nil {
			fmt.Printf("%s Failed to cleanup: %v\n", yellow("⚠️"), err)
		}
		if err := ruleManager.SaveRules(); err != nil {
			fmt.Printf("%s Failed to save rules: %v\n", yellow("⚠️"), err)
		}

		fmt.Printf("%s Persistent firewall rules remain active\n", faint("ℹ️"))
		fmt.Printf("%s Use 'cli-snitch clear-firewall' to remove all rules\n", faint("💡"))
		fmt.Println(green("✅ Cleanup complete. Goodbye!"))
	},
}

// handleNewConnection processes a new connection through the decision pipeline
func handleNewConnection(
	conn *monitor.Connection,
	ruleManager *rules.RuleManager,
	prompter *prompt.ConnectionPrompter,
	firewallManager *firewall.FirewallManager,
	history *monitor.ConnectionHistory,
	systemStats *SystemStats,
) {
	connInfo := rules.ConnectionInfo{
		ProcessName: conn.ProcessName,
		Host:        conn.RemoteAddr,
		Port:        conn.RemotePort,
	}

	// Check existing rules
	if existingRule, found := ruleManager.FindMatchingRule(connInfo); found {
		switch existingRule.Action {
		case rules.Allow, rules.AllowOnce:
			fmt.Printf("%s %s %s -> %s:%s [%s]\n",
				green("✅"), cyan(conn.ProcessName), green("ALLOWED"),
				conn.RemoteAddr, conn.RemotePort, faint(existingRule.Description))
			history.LogConnection(conn, "allowed")
		case rules.Deny, rules.DenyOnce:
			fmt.Printf("%s %s %s -> %s:%s [%s]\n",
				red("❌"), cyan(conn.ProcessName), red("DENIED"),
				conn.RemoteAddr, conn.RemotePort, faint(existingRule.Description))
			history.LogConnection(conn, "denied")
		}

		if existingRule.Action == rules.AllowOnce || existingRule.Action == rules.DenyOnce {
			ruleManager.DeleteRule(existingRule.ID)
		}
		return
	}

	// No rule — prompt user (serialized via queue)
	fmt.Printf("%s %s New connection: %s -> %s:%s\n",
		yellow("🔍"), cyan(conn.ProcessName),
		conn.RemoteAddr, conn.RemotePort, faint("(awaiting decision)"))

	decision, err := prompter.QueuePrompt(conn)
	if err != nil {
		fmt.Printf("%s Failed to get decision: %v\n", red("❌"), err)
		decision = &prompt.UserDecision{
			Action:      rules.AllowOnce,
			Scope:       rules.Exact,
			Description: "Auto-allowed due to prompt error",
		}
	}

	// Apply decision
	switch decision.Action {
	case rules.Allow, rules.AllowOnce:
		fmt.Printf("%s %s %s -> %s:%s\n",
			green("✅"), cyan(conn.ProcessName), green("ALLOWED"),
			conn.RemoteAddr, conn.RemotePort)
		history.LogConnection(conn, "allowed")

	case rules.Deny, rules.DenyOnce:
		fmt.Printf("%s %s %s -> %s:%s\n",
			red("❌"), cyan(conn.ProcessName), red("DENIED"),
			conn.RemoteAddr, conn.RemotePort)
		history.LogConnection(conn, "denied")

		firewallRule := firewallManager.CreateBlockRuleFromUserDecision(decision, conn.ProcessName, conn.RemoteAddr, conn.RemotePort)
		if firewallRule != nil {
			pfRule, err := firewallManager.GeneratePfRule(firewallRule)
			if err != nil {
				fmt.Printf("%s Failed to generate rule: %v\n", red("❌"), err)
			} else {
				fmt.Printf("%s Firewall rule: %s\n", faint("🔥"), faint(pfRule))
			}

			if err := firewallManager.AddBlockRule(firewallRule); err != nil {
				fmt.Printf("%s Failed to apply rule: %v\n", red("❌"), err)
			} else {
				fmt.Printf("%s Firewall rule applied\n", green("🛡️"))
			}
		}
	}

	// Save persistent rules
	if decision.Action == rules.Allow || decision.Action == rules.Deny {
		rule := rules.Rule{
			ProcessName: conn.ProcessName,
			Action:      decision.Action,
			Scope:       decision.Scope,
			Description: decision.Description,
		}

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

	systemStats.incrRules()
}
