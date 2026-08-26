package fixgen

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"
	"time"

	"lain/internal/scorer"
	"lain/internal/types"
)

type cannedFix struct {
	RootCause       string
	FixInstructions string
}

// fallbackFixes is the offline safety net used when no LLM client/API key is
// available or the LLM call fails.
var fallbackFixes = map[string]cannedFix{
	scorer.TypeSQLi: {
		RootCause:       "The application concatenates user-controlled input into a SQL statement instead of using parameterized queries, so crafted input can change the query's structure and bypass the WHERE clause.",
		FixInstructions: "Rewrite the query to use prepared statements with placeholders (e.g. ? or $1) and pass the parameter value separately; never build SQL by string concatenation.",
	},
	scorer.TypeXSS: {
		RootCause:       "User input is reflected into an HTML response without output encoding, so injected markup or script executes in the victim's browser.",
		FixInstructions: "Apply context-appropriate output encoding (HTML-escape) to the reflected value in the response template, e.g. use html/template instead of interpolating into a raw fmt.Sprintf string.",
	},
	scorer.TypePathTraversal: {
		RootCause:       "A filesystem path is built by joining a base directory with unvalidated user input, allowing ../ sequences to escape the intended directory.",
		FixInstructions: "Resolve the request to an absolute path and verify it stays under the allowed base directory (filepath.Clean plus a prefix check); reject inputs containing .. or path separators.",
	},
	scorer.TypeUnauthRoute: {
		RootCause:       "This sensitive route returns data without any authentication or authorization check, so anyone can reach it.",
		FixInstructions: "Add an authentication/authorization guard to this handler (session/JWT check) and return 401/403 when the caller is not permitted.",
	},
}

var fallbackUnknown = cannedFix{
	RootCause:       "User-controlled input reaches a sensitive operation without validation at the boundary.",
	FixInstructions: "Review the reported handler and parameter, validate and encode input at the boundary, then re-run the scan to confirm remediation.",
}

func fallbackFor(vulnType string) cannedFix {
	if f, ok := fallbackFixes[vulnType]; ok {
		return f
	}
	return fallbackUnknown
}

type fixSectionData struct {
	types.Finding
	RootCause       string
	FixInstructions string
	SeverityBadge   string
}

func severityBadge(severity string) string {
	switch severity {
	case "HIGH":
		return "🔴 HIGH"
	case "MEDIUM":
		return "🟡 MEDIUM"
	default:
		return "🟢 LOW"
	}
}

const fixSectionTemplateText = `## [{{.SeverityBadge}}] {{.Title}} — {{.Route.Method}} {{.Route.Path}}

**Location:** ` + "`" + `{{.Location}}` + "`" + `
**Finding ID:** ` + "`" + `{{.ID}}` + "`" + `

### Evidence
{{.Evidence}}

### Root Cause
{{.RootCause}}

### Suggested Fix
{{.FixInstructions}}

### Acceptance Check
Lain will re-scan this route on the next push to confirm remediation (finding ID ` + "`" + `{{.ID}}` + "`" + `).
`

var fixSectionTemplate = template.Must(template.New("fixSection").Parse(fixSectionTemplateText))

// GenerateFixSection renders a markdown fix section for a single finding. When
// the client is enabled, the LLM is consulted (with graceful fallback on error);
// otherwise the canned fallback table is used directly.
func GenerateFixSection(finding types.Finding, client *LLMClient) string {
	rootCause, fixInstructions := "", ""

	if client != nil && client.Enabled {
		rc, fi, err := client.Explain(finding)
		if err != nil {
			log.Printf("fixgen: LLM explain failed for %s, using fallback: %v", finding.Location, err)
		} else {
			rootCause, fixInstructions = rc, fi
		}
	}

	if rootCause == "" {
		fallback := fallbackFor(finding.VulnType)
		rootCause, fixInstructions = fallback.RootCause, fallback.FixInstructions
	}

	var buf bytes.Buffer
	if err := fixSectionTemplate.Execute(&buf, fixSectionData{
		Finding:         finding,
		RootCause:       rootCause,
		FixInstructions: fixInstructions,
		SeverityBadge:   severityBadge(finding.Severity),
	}); err != nil {
		log.Printf("fixgen: template render failed for %s: %v", finding.Location, err)
		return ""
	}
	return buf.String()
}

// WriteFixMD writes a top-level fix report with a how-to-use note, a scannable
// summary table, and one detailed section per finding.
func WriteFixMD(result types.ScanResult, client *LLMClient, path string) error {
	var b strings.Builder
	b.WriteString("# Lain Fix Report\n\n")
	b.WriteString("> **How to use this file:** paste it into your AI coding assistant (Cursor, Claude Code, Copilot Chat) and ask it to apply the fixes below. Each fix references the exact route and finding ID so Lain can verify remediation on the next scan.\n\n")
	b.WriteString(fmt.Sprintf("**%d finding(s), generated %s**\n\n", len(result.Findings), time.Now().Format(time.RFC3339)))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Finding ID | Severity | Type | Location |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, f := range result.Findings {
		b.WriteString(fmt.Sprintf("| `%s` | %s | %s | `%s` |\n", f.ID, severityBadge(f.Severity), f.Title, f.Location))
	}
	b.WriteString("\n---\n\n")

	for _, f := range result.Findings {
		b.WriteString(GenerateFixSection(f, client))
		b.WriteString("\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}
