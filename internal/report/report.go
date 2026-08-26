package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"lain/internal/types"
)

// Hand-rolled minimal SARIF 2.1.0 subset — only the fields lain emits.

type SarifText struct {
	Text string `json:"text"`
}

type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SarifRule `json:"rules,omitempty"`
}

type SarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription SarifText `json:"shortDescription,omitempty"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifText       `json:"message"`
	Locations []SarifLocation `json:"locations,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func sarifLevel(severity string) string {
	switch severity {
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func ToSarif(result types.ScanResult) SarifLog {
	log := SarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SarifRun{{
			Tool: SarifTool{Driver: SarifDriver{Name: "lain", Version: "0.1.0"}},
		}},
	}
	run := &log.Runs[0]

	for _, f := range result.Findings {
		ruleID := f.ID
		if ruleID == "" {
			ruleID = "LAIN-UNKNOWN"
		}
		run.Tool.Driver.Rules = appendUniqueRule(run.Tool.Driver.Rules, SarifRule{
			ID:               ruleID,
			Name:             f.Title,
			ShortDescription: SarifText{Text: f.Title},
		})

		run.Results = append(run.Results, SarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: SarifText{Text: fmt.Sprintf("%s — %s", f.Title, f.Location)},
			Locations: []SarifLocation{{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{URI: f.Route.Path},
				},
			}},
		})
	}

	return log
}

func appendUniqueRule(rules []SarifRule, rule SarifRule) []SarifRule {
	for _, r := range rules {
		if r.ID == rule.ID {
			return rules
		}
	}
	return append(rules, rule)
}

func WriteSarifJSON(log SarifLog, path string) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func WriteMarkdownReport(result types.ScanResult, path string) error {
	var b strings.Builder

	counts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	b.WriteString("# Lain Security Scan Report\n\n")
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|---|---|\n")
	b.WriteString(fmt.Sprintf("| Routes scanned | %d |\n", result.TargetsScanned))
	b.WriteString(fmt.Sprintf("| Total findings | %d |\n", len(result.Findings)))
	b.WriteString(fmt.Sprintf("| HIGH | %d |\n", counts["HIGH"]))
	b.WriteString(fmt.Sprintf("| MEDIUM | %d |\n", counts["MEDIUM"]))
	b.WriteString(fmt.Sprintf("| LOW | %d |\n", counts["LOW"]))
	b.WriteString(fmt.Sprintf("| Duration | %s |\n", result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond)))

	b.WriteString("\n## Findings\n\n")
	b.WriteString("| Severity | Title | Location | Evidence |\n")
	b.WriteString("|---|---|---|---|\n")

	for _, sev := range []string{"HIGH", "MEDIUM", "LOW"} {
		for _, f := range result.Findings {
			if f.Severity != sev {
				continue
			}
			evidence := truncate(f.Evidence, 80)
			if evidence == "" {
				evidence = "—"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n", f.Severity, f.Title, f.Location, evidence))
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}
