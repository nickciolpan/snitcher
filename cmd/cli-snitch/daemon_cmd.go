package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const launchdPlistName = "com.cli-snitch.daemon"

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage CLI Snitch background daemon",
	Long:  `Install, start, stop, or check the status of the CLI Snitch background daemon via launchd.`,
}

var daemonInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the launchd daemon",
	Run: func(cmd *cobra.Command, args []string) {
		binaryPath, err := os.Executable()
		if err != nil {
			fmt.Printf("%s Failed to get executable path: %v\n", red("❌"), err)
			os.Exit(1)
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("%s Failed to get home dir: %v\n", red("❌"), err)
			os.Exit(1)
		}

		logPath := filepath.Join(homeDir, ".cli-snitch", "daemon.log")
		errLogPath := filepath.Join(homeDir, ".cli-snitch", "daemon.err.log")

		// Ensure log directory exists
		os.MkdirAll(filepath.Join(homeDir, ".cli-snitch"), 0755)

		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>watch</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
`, launchdPlistName, binaryPath, logPath, errLogPath)

		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", launchdPlistName)

		if os.Geteuid() != 0 {
			fmt.Printf("%s Installing the daemon requires root privileges\n", red("❌"))
			fmt.Printf("   Run: sudo cli-snitch daemon install\n")
			os.Exit(1)
		}

		if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
			fmt.Printf("%s Failed to write plist: %v\n", red("❌"), err)
			os.Exit(1)
		}

		fmt.Printf("%s Daemon plist installed at %s\n", green("✅"), plistPath)
		fmt.Printf("%s Logs: %s\n", faint("📄"), logPath)
		fmt.Printf("%s To start: sudo cli-snitch daemon start\n", faint("💡"))
	},
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			fmt.Printf("%s Starting the daemon requires root\n", red("❌"))
			fmt.Printf("   Run: sudo cli-snitch daemon start\n")
			os.Exit(1)
		}

		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", launchdPlistName)
		if _, err := os.Stat(plistPath); os.IsNotExist(err) {
			fmt.Printf("%s Daemon not installed. Run: sudo cli-snitch daemon install\n", red("❌"))
			os.Exit(1)
		}

		output, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
		if err != nil {
			fmt.Printf("%s Failed to start daemon: %v\n%s\n", red("❌"), err, string(output))
			os.Exit(1)
		}

		fmt.Printf("%s Daemon started\n", green("✅"))
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			fmt.Printf("%s Stopping the daemon requires root\n", red("❌"))
			fmt.Printf("   Run: sudo cli-snitch daemon stop\n")
			os.Exit(1)
		}

		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", launchdPlistName)
		output, err := exec.Command("launchctl", "unload", plistPath).CombinedOutput()
		if err != nil {
			fmt.Printf("%s Failed to stop daemon: %v\n%s\n", red("❌"), err, string(output))
			os.Exit(1)
		}

		fmt.Printf("%s Daemon stopped\n", green("✅"))
	},
}

var daemonUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			fmt.Printf("%s Uninstalling requires root\n", red("❌"))
			os.Exit(1)
		}

		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", launchdPlistName)

		// Try to stop first
		exec.Command("launchctl", "unload", plistPath).Run()

		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("%s Failed to remove plist: %v\n", red("❌"), err)
			os.Exit(1)
		}

		fmt.Printf("%s Daemon uninstalled\n", green("✅"))
	},
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	Run: func(cmd *cobra.Command, args []string) {
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", launchdPlistName)

		if _, err := os.Stat(plistPath); os.IsNotExist(err) {
			fmt.Printf("%s Daemon: not installed\n", yellow("⚠️"))
			return
		}

		fmt.Printf("%s Daemon: installed\n", green("✅"))

		// Check if running via launchctl list <label> which returns PID, exit status, label
		output, err := exec.Command("launchctl", "list", launchdPlistName).CombinedOutput()
		if err != nil {
			fmt.Printf("%s Status: not loaded\n", yellow("⚠️"))
			return
		}

		// Parse output — first line after header has: PID \t Status \t Label
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] == launchdPlistName {
				if fields[0] != "-" {
					pid, _ := strconv.Atoi(fields[0])
					fmt.Printf("%s Status: running (PID %d)\n", green("✅"), pid)
				} else {
					fmt.Printf("%s Status: loaded but not running (exit %s)\n", yellow("⚠️"), fields[1])
				}
				return
			}
		}
		fmt.Printf("%s Status: running\n", green("✅"))
	},
}

func init() {
	daemonCmd.AddCommand(daemonInstallCmd)
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonUninstallCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
}
