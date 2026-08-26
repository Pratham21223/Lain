package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lain/internal/types"
)

func fakeResult() types.ScanResult {
	now := time.Now()
	return types.ScanResult{
		Findings: []types.Finding{
			{
				ID:       "a1b2c3d4",
				Title:    "SQL Injection",
				Severity: "HIGH",
				Route:    types.Route{Method: "GET", Path: "/api/users"},
				Param:    "id",
				Location: "GET /api/users?id",
				Evidence: "response body contains \"syntax error\" plus a very long explanation that should get truncated to eighty characters for the markdown table",
			},
			{
				ID:       "e5f6a7b8",
				Title:    "Reflected XSS",
				Severity: "MEDIUM",
				Route:    types.Route{Method: "GET", Path: "/search"},
				Param:    "q",
				Location: "GET /search?q",
				Evidence: "payload reflected unescaped in response body",
			},
			{
				ID:       "c9d0e1f2",
				Title:    "Cookie without HttpOnly",
				Severity: "LOW",
				Route:    types.Route{Method: "GET", Path: "/login"},
				Location: "GET /login",
				Evidence: "",
			},
		},
		TargetsScanned: 3,
		StartedAt:      now.Add(-2 * time.Second),
		FinishedAt:     now,
	}
}

func TestWriteReports(t *testing.T) {
	result := fakeResult()
	dir := t.TempDir()
	sarifPath := filepath.Join(dir, "report.json")
	mdPath := filepath.Join(dir, "report.md")

	if err := WriteSarifJSON(ToSarif(result), sarifPath); err != nil {
		t.Fatalf("WriteSarifJSON: %v", err)
	}
	if err := WriteMarkdownReport(result, mdPath); err != nil {
		t.Fatalf("WriteMarkdownReport: %v", err)
	}

	sarifData, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("reading sarif: %v", err)
	}
	mdData, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("reading markdown: %v", err)
	}

	sarif := string(sarifData)
	for _, want := range []string{
		`"version": "2.1.0"`,
		`"name": "lain"`,
		"/api/users",
		`"level": "error"`,
		`"level": "warning"`,
		`"level": "note"`,
		"a1b2c3d4",
	} {
		if !strings.Contains(sarif, want) {
			t.Errorf("sarif output missing %q", want)
		}
	}

	md := string(mdData)
	for _, want := range []string{
		"Lain Security Scan Report",
		"Routes scanned",
		"Total findings",
		"| HIGH | 1 |",
		"| MEDIUM | 1 |",
		"| LOW | 1 |",
		"GET /api/users?id",
		"GET /search?q",
		"GET /login",
		"SQL Injection",
		"Reflected XSS",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestWriteHTMLReport(t *testing.T) {
	result := fakeResult()
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")

	if err := WriteHTMLReport(result, "http://localhost:5000", "owner/repo", htmlPath); err != nil {
		t.Fatalf("WriteHTMLReport: %v", err)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading html: %v", err)
	}
	html := string(data)

	for _, want := range []string{
		"Lain Security Scan Report",
		"http://localhost:5000",
		"const DATA =",
		"SQL Injection",
		"Reflected XSS",
		"Cookie without HttpOnly",
		"GET /api/users?id",
		"GET /search?q",
		"GET /login",
		"a1b2c3d4",
		`"routesScanned":3`,
		`"severity":"HIGH"`,
		`"severity":"MEDIUM"`,
		`"severity":"LOW"`,
		`"githubRepo":"owner/repo"`,
		"Create issue",
		"api.github.com",
		"PASSED",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html output missing %q", want)
		}
	}
}

// TestHTMLReportEscapesPayloads is the safety property of the dashboard: real
// XSS payloads discovered by the fuzzer must never appear as raw HTML in the
// report, otherwise opening the report could execute them.
func TestHTMLReportEscapesPayloads(t *testing.T) {
	result := fakeResult()
	result.Findings = append(result.Findings, types.Finding{
		ID:       "xss1337",
		Title:    "Reflected XSS",
		Severity: "MEDIUM",
		Location: "GET /p?q",
		Payload:  `<script>alert(document.cookie)</script>`,
		Evidence: `"><img src=x onerror=alert(1)> & <svg/onload=alert(2)>`,
	})
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	if err := WriteHTMLReport(result, "http://localhost:5000", "", htmlPath); err != nil {
		t.Fatalf("WriteHTMLReport: %v", err)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading html: %v", err)
	}
	html := string(data)

	for _, forbidden := range []string{
		"<script>alert",
		"<img src=x",
		"<svg/onload",
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("html contains unescaped payload %q — the report could execute it", forbidden)
		}
	}
	// The data must still be present, safely JSON-escaped inside the script blob.
	for _, escaped := range []string{
		`\u003cscript\u003ealert`,
		`\u003cimg`,
		`\u003csvg`,
		`\u0026 \u003c`,
	} {
		if !strings.Contains(html, escaped) {
			t.Errorf("expected JSON-escaped payload %q to be present", escaped)
		}
	}
}

func TestHTMLVerdictFailedOnHigh(t *testing.T) {
	result := fakeResult()
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	if err := WriteHTMLReport(result, "", "", htmlPath); err != nil {
		t.Fatalf("WriteHTMLReport: %v", err)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"verdict":"FAILED"`) {
		t.Error("expected FAILED verdict when HIGH findings exist")
	}
}

func TestMarkdownGroupsHighFirst(t *testing.T) {
	result := fakeResult()
	dir := t.TempDir()
	mdPath := filepath.Join(dir, "report.md")

	if err := WriteMarkdownReport(result, mdPath); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(md)

	high := strings.Index(text, "| HIGH | SQL Injection")
	medium := strings.Index(text, "| MEDIUM | Reflected XSS")
	low := strings.Index(text, "| LOW | Cookie without HttpOnly")

	if high == -1 || medium == -1 || low == -1 {
		t.Fatalf("expected all severity rows present (high=%d medium=%d low=%d)", high, medium, low)
	}
	if !(high < medium && medium < low) {
		t.Errorf("findings must be ordered HIGH, MEDIUM, LOW (got high=%d medium=%d low=%d)", high, medium, low)
	}
}

func TestMarkdownTruncatesEvidence(t *testing.T) {
	result := fakeResult()
	dir := t.TempDir()
	mdPath := filepath.Join(dir, "report.md")

	if err := WriteMarkdownReport(result, mdPath); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}

	start := strings.Index(string(md), "response body contains \"syntax error\"")
	if start == -1 {
		t.Fatal("expected truncated evidence text")
	}
	end := strings.Index(string(md[start:]), "|")
	if end == -1 {
		t.Fatal("expected evidence cell to end")
	}
	evidence := strings.TrimSpace(string(md)[start : start+end])
	if len(evidence) != 83 {
		t.Errorf("evidence should be truncated to 80 chars + \"...\" (=83), got %d chars (%q)", len(evidence), evidence)
	}
}
