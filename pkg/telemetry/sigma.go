package telemetry

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
	"aftersec/pkg/client/storage"
)

// SigmaRule represents a generic detection rule based on the Sigma format.
type SigmaRule struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Level       string `yaml:"level"`
	LogSource   struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
	} `yaml:"logsource"`
	Detection struct {
		Condition string                   `yaml:"condition"`
		Selection map[string]interface{}   `yaml:"selection"`
	} `yaml:"detection"`
}

// ParseSigmaRule parses a YAML byte array into a SigmaRule struct.
func ParseSigmaRule(data []byte) (*SigmaRule, error) {
	var rule SigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// CompileToSQL translates a basic Sigma rule selection block into a SQLite compatible query
// using the json_extract() function against the 'telemetry_events' table.
func CompileToSQL(rule *SigmaRule) (string, []interface{}, error) {
	if len(rule.Detection.Selection) == 0 {
		return "", nil, fmt.Errorf("empty selection criteria")
	}

	var conditions []string
	var args []interface{}

	// Map standard Sigma fields to AfterSec ESF/Unified Log JSON keys
	fieldMapping := map[string]string{
		"Image":       "$.process.executable",
		"CommandLine": "$.process.command_line",
		"ParentImage": "$.process.parent_executable",
		"TargetFilename": "$.file.path",
		"DestinationIp":  "$.network.destination.ip",
		"DestinationPort": "$.network.destination.port",
	}

	for key, val := range rule.Detection.Selection {
		parts := strings.Split(key, "|")
		field := parts[0]
		modifier := ""
		if len(parts) > 1 {
			modifier = parts[1]
		}

		jsonPath, ok := fieldMapping[field]
		if !ok {
			// Fallback: assume the field directly maps to a flat json key
			jsonPath = "$." + strings.ToLower(field)
		}

		strVal, isStr := val.(string)
		if !isStr {
			// Basic support for non-string values (int/bool)
			conditions = append(conditions, fmt.Sprintf("json_extract(details, '%s') = ?", jsonPath))
			args = append(args, val)
			continue
		}

		switch modifier {
		case "contains":
			conditions = append(conditions, fmt.Sprintf("json_extract(details, '%s') LIKE ?", jsonPath))
			args = append(args, "%"+strVal+"%")
		case "startswith":
			conditions = append(conditions, fmt.Sprintf("json_extract(details, '%s') LIKE ?", jsonPath))
			args = append(args, strVal+"%")
		case "endswith":
			conditions = append(conditions, fmt.Sprintf("json_extract(details, '%s') LIKE ?", jsonPath))
			args = append(args, "%"+strVal)
		default:
			// Exact match or wildcard match
			if strings.Contains(strVal, "*") {
				conditions = append(conditions, fmt.Sprintf("json_extract(details, '%s') LIKE ?", jsonPath))
				sqlLike := strings.ReplaceAll(strVal, "*", "%")
				args = append(args, sqlLike)
			} else {
				conditions = append(conditions, fmt.Sprintf("json_extract(details, '%s') = ?", jsonPath))
				args = append(args, strVal)
			}
		}
	}

	// Basic logsource filtering if provided
	if rule.LogSource.Category != "" {
		conditions = append(conditions, "event_type = ?")
		args = append(args, rule.LogSource.Category)
	}

	whereClause := strings.Join(conditions, " AND ")
	query := fmt.Sprintf("SELECT id, timestamp, source, event_type, severity, details FROM telemetry_events WHERE %s ORDER BY timestamp DESC LIMIT 1000", whereClause)

	return query, args, nil
}

// RunHunt executes a compiled Sigma rule against the local AfterSec SQLite telemetry database.
func RunHunt(mgr *storage.SQLiteManager, rule *SigmaRule) ([]map[string]interface{}, error) {
	query, args, err := CompileToSQL(rule)
	if err != nil {
		return nil, err
	}
	return mgr.QueryTelemetry(query, args...)
}
