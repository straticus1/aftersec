package darkapi

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func Severity(s string) string {
	switch s {
	case "critical":
		return s
	case "high", "very-high":
		return "high"
	case "medium", "med":
		return "medium"
	case "low":
		return s
	case "warning":
		return s
	default:
		return "info"
	}
}

// redact removes credential-bearing fields before upload; it never executes remediation content.
func redact(data map[string]any) map[string]any {
	result := make(map[string]any, len(data))
	for key, value := range data {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "api_key") || strings.Contains(lower, "private_key") {
			result[key] = "[redacted]"
			continue
		}
		value = redactValue(value)
		result[key] = value
	}
	return result
}
func redactValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return redact(v)
	case []any:
		result := make([]any, len(v))
		for i, child := range v {
			result[i] = redactValue(child)
		}
		return result
	default:
		return value
	}
}
