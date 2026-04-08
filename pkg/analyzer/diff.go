package analyzer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Compare analyzes the differences between UserA, UserB, and Unauthenticated.
// Returns a boolean indicating if BOLA is likely, and a float64 indicating the structural match percentage.
func Compare(respA, respB, respU []byte, codeA, codeB, codeU int) (bool, float64) {
	if codeA < 200 || codeA >= 300 {
		return false, 0.0
	}
	if codeB < 200 || codeB >= 300 {
		return false, 0.0
	}

	var jsonA, jsonB interface{}
	errA := json.Unmarshal(respA, &jsonA)
	errB := json.Unmarshal(respB, &jsonB)

	// If not JSON, we revert to naive exact matching
	if errA != nil || errB != nil {
		if string(respA) == string(respB) && string(respA) != string(respU) {
			return true, 1.0
		}
		return false, 0.0
	}

	// Filter identical 200 OK generic errors before running AST
	if isGenericError(jsonA) {
		return false, 0.0
	}

	// HEURISTIC 1: Filter generic Empty Envelopes ({"success": true, "data": []})
	if !isMeaningfulData(jsonA) || !isMeaningfulData(jsonB) {
		return false, 0.0
	}

	// ⭐️ The AST Engine ⭐️
	structA := getStructure(jsonA)
	structB := getStructure(jsonB)

	// If the structure matches exactly
	if reflect.DeepEqual(structA, structB) {
		var jsonU interface{}
		if errU := json.Unmarshal(respU, &jsonU); errU == nil {
			structU := getStructure(jsonU)
			// Ensure Unauthenticated user didn't also get the exact same structure
			if reflect.DeepEqual(structA, structU) {
				return false, 1.0 // Endpoint is public
			}
		}

		// HEURISTIC 2: Measure leaf data similarity (The Own-Profile Flaw)
		similarity := calculateDataSimilarity(jsonA, jsonB)
		if similarity < 0.5 {
			// Values diverged drastically. The API returned the attacker's own profile, not the victim's data.
			return false, similarity
		}

		// BOLA Confirmed! Exact structural match AND >50% of the data values match (indicating victim data leak)
		return true, similarity 
	}

	return false, 0.0
}

// isMeaningfulData recursively ensures the JSON actually contains domain-specific values, not just generic wrappers
func isMeaningfulData(v interface{}) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		meaningfulCount := 0
		genericKeys := map[string]bool{
			"status": true, "success": true, "error": true, "errors": true,
			"message": true, "code": true, "data": true, "meta": true, "ok": true,
		}
		
		for k, child := range val {
			if !genericKeys[strings.ToLower(k)] {
				meaningfulCount++
			}
			// If child arrays or objects contain meaningful sub-data, it counts
			if isMeaningfulData(child) {
				meaningfulCount++
			}
		}
		return meaningfulCount > 0
		
	case []interface{}:
		if len(val) == 0 {
			return false // Empty arrays are meaningless 
		}
		for _, item := range val {
			if isMeaningfulData(item) {
				return true
			}
		}
		return false
		
	case string, float64, bool:
		if s, ok := val.(string); ok && strings.TrimSpace(s) == "" {
			return false
		}
		return true
	default:
		return false
	}
}

// getLeafValues flattens a JSON structure into a dictionary of paths -> stringified primitive values
func getLeafValues(v interface{}, prefix string, leaves map[string]string) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			getLeafValues(child, prefix+"."+k, leaves)
		}
	case []interface{}:
		for i, child := range val {
			getLeafValues(child, fmt.Sprintf("%s[%d]", prefix, i), leaves)
		}
	case float64:
		leaves[prefix] = fmt.Sprintf("%v", val)
	case string:
		leaves[prefix] = val
	case bool:
		leaves[prefix] = fmt.Sprintf("%v", val)
	}
}

// calculateDataSimilarity measures what percentage of the actual primitive values match between two structs
func calculateDataSimilarity(jsonA, jsonB interface{}) float64 {
	leavesA := make(map[string]string)
	leavesB := make(map[string]string)
	
	getLeafValues(jsonA, "root", leavesA)
	getLeafValues(jsonB, "root", leavesB)
	
	if len(leavesA) == 0 && len(leavesB) == 0 {
		return 1.0
	}
	
	matchCount := 0
	totalCount := len(leavesA)
	if totalCount == 0 {
		totalCount = 1
	}
	
	for path, valA := range leavesA {
		if valB, exists := leavesB[path]; exists && valA == valB {
			matchCount++
		}
	}
	
	return float64(matchCount) / float64(totalCount)
}

// getStructure converts a JSON payload into its AST structural skeleton by mapping data types
func getStructure(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		m := make(map[string]interface{})
		for k, child := range val {
			m[k] = getStructure(child)
		}
		return m
	case []interface{}:
		if len(val) > 0 {
			return []interface{}{getStructure(val[0])}
		}
		return []interface{}{}
	case string:
		return "STRING"
	case float64:
		return "NUMBER"
	case bool:
		return "BOOL"
	default:
		return "NULL"
	}
}

// isGenericError checks if a parsed JSON response represents a generic failure despite the HTTP 200 Code
func isGenericError(v interface{}) bool {
	val, ok := v.(map[string]interface{})
	if !ok {
		return false
	}

	if _, hasError := val["error"]; hasError {
		return true
	}
	if _, hasErrors := val["errors"]; hasErrors {
		return true
	}

	if status, hasStatus := val["status"]; hasStatus {
		if s, ok := status.(string); ok && (s == "error" || s == "fail" || s == "false") {
			return true
		}
		if b, ok := status.(bool); ok && !b {
			return true
		}
	}

	if msg, hasMsg := val["message"]; hasMsg {
		if s, ok := msg.(string); ok {
			s = strings.ToLower(s)
			if strings.Contains(s, "unauthorized") || strings.Contains(s, "forbidden") {
				return true
			}
		}
	}

	return false
}
