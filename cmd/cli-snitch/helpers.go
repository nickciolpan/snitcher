package main

import (
	"os"
	"path/filepath"
)

func getRulesFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".cli-snitch/rules.json"
	}
	return filepath.Join(homeDir, ".cli-snitch", "rules.json")
}

func getHistoryFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".cli-snitch/history.jsonl"
	}
	return filepath.Join(homeDir, ".cli-snitch", "history.jsonl")
}
