package access

import (
	"fmt"
	"strings"
)

// NormalizeFailOnSeverity validates the explicit local policy threshold used
// by CLI/TUI audit gates. An empty value or "none" disables the gate.
func NormalizeFailOnSeverity(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "none" {
		return "", nil
	}
	switch value {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return value, nil
	default:
		return "", fmt.Errorf("invalid --fail-on severity %q; use critical, high, medium, low, info, or none", value)
	}
}

// CountFindingsAtOrAbove returns how many findings meet the selected severity
// threshold. For example, "high" matches high and critical findings.
func CountFindingsAtOrAbove(findings []Finding, threshold string) (int, error) {
	normalized, err := NormalizeFailOnSeverity(threshold)
	if err != nil || normalized == "" {
		return 0, err
	}
	thresholdRank := severityRank(normalized)
	count := 0
	for index, finding := range findings {
		severity, err := NormalizeFailOnSeverity(finding.Severity)
		if err != nil || severity == "" {
			return 0, fmt.Errorf("finding %d has invalid severity %q", index, finding.Severity)
		}
		if severityRank(severity) <= thresholdRank {
			count++
		}
	}
	return count, nil
}
