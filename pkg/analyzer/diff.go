package analyzer

import (
	"encoding/json"
	"reflect"
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

	// If not JSON, we revert to naive exact matching (for MVP of Phase 3)
	if errA != nil || errB != nil {
		if string(respA) == string(respB) && string(respA) != string(respU) {
			return true, 1.0
		}
		return false, 0.0
	}

	// ⭐️ The AST Engine ⭐️
	// Instead of cleaning noisy keys and comparing lengths, we build a "Structure Skeleton".
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
		return true, 1.0 // BOLA Confirmed! Exact structural match regardless of dynamic values
	}

	return false, 0.0
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
		// For arrays, we just capture the structure of the first entry assuming uniformity,
		// or we return an empty array type.
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
