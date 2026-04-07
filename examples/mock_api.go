package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type FinancialData struct {
	Balance    int    `json:"balance"`
	CardNumber string `json:"card_number"`
	Timestamp  string `json:"timestamp"` // We add timestamp to simulate dynamic API noise
}

func main() {
	http.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")
		// Check if user is logged in
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
			return
		}

		// Extract target user ID from URL: /api/v1/users/{id}/financial_data
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		targetUserID := parts[4]

		// ⭐ THE DELIBERATE BOLA VULNERABILITY ⭐
		// Notice we NEVER check if the token belongs to the targetUserID!
		// We blindly trust that if you have a valid token, you can view the requested ID.

		var data FinancialData
		if targetUserID == "100" { // User A (Victim)
			data = FinancialData{Balance: 5000, CardNumber: "****-1234", Timestamp: time.Now().Format(time.RFC3339Nano)}
		} else if targetUserID == "200" { // User B (Attacker)
			data = FinancialData{Balance: 95000, CardNumber: "****-9999", Timestamp: time.Now().Format(time.RFC3339Nano)}
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "user not found"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(data)
	})

	fmt.Println("[\u001b[31m!\u001b[0m] Mock VULNERABLE API Server Running on port 8888...")
	fmt.Println("[\u001b[36m*\u001b[0m] Vulnerable Endpoint: http://localhost:8888/api/v1/users/100/financial_data")
	err := http.ListenAndServe("127.0.0.1:8888", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
