package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// PrintBanner prints the ASCII banner for AuthSniper
func PrintBanner() {
	banner := `
    ___         __  __  _____       _                 
   /   | __  __/ /_/ / / ___/____  (_)___  ___  _____ 
  / /| |/ / / / __/ /_ \__ \/ __ \/ / __ \/ _ \/ ___/ 
 / ___ / /_/ / /_/ __ \___/ / / / / / /_/ /  __/ /    
/_/  |_\\__,_/\\__/_/ /_/____/_/ /_/_/ .___/\\___/_/     
                                  /_/                 
	`
	fmt.Println("\033[36m" + banner + "\033[0m")
	fmt.Println("\033[90mThe Ultimate API BOLA/IDOR Hunter v1.0\033[0m")
	fmt.Println("\033[90m======================================\033[0m")
	fmt.Println()
}

// PrintSuccess prints a successful finding
func PrintSuccess(endpoint string, percentMatch float64) {
	fmt.Printf("[\033[32m+\033[0m] \033[1;31mBOLA/IDOR VULNERABILITY DETECTED\033[0m - %s (Structure Match: %.2f%%)\n", endpoint, percentMatch*100)
}

// PrintInfo prints informational logs
func PrintInfo(msg string) {
	fmt.Printf("[\033[36m*\033[0m] %s\n", msg)
}

// PrintWarning prints warnings (e.g. false positives filtered)
func PrintWarning(msg string) {
	fmt.Printf("[\033[33m!\033[0m] %s\n", msg)
}

// PrintError prints errors
func PrintError(msg string) {
	fmt.Printf("[\033[31m-\033[0m] %s\n", msg)
}

// JSONLRecord is the struct for the JSONL output line
type JSONLRecord struct {
	Timestamp    string  `json:"timestamp"`
	Target       string  `json:"target"`
	MatchPercent float64 `json:"match_percent"`
	Risk         string  `json:"risk"`
}

// WriteJSONL appends finding to a JSON lines file for CI/CD integration
func WriteJSONL(path, target string, score float64) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		PrintError("Could not write to output file: " + err.Error())
		return
	}
	defer f.Close()

	rec := JSONLRecord{
		Timestamp:    time.Now().Format(time.RFC3339),
		Target:       target,
		MatchPercent: score * 100,
		Risk:         "HIGH - BOLA",
	}

	data, _ := json.Marshal(rec)
	f.Write(append(data, '\n'))
}
