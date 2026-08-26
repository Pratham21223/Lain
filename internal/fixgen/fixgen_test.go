package fixgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lain/internal/scorer"
	"lain/internal/types"
)

// TestGenerateFixSectionFallback exercises only the fallback path: the client
// is disabled so no LLM call is made and tests stay fast and offline. The
// LLM-path is covered by llm_test.go's mock-server tests; a live check is a
// manual step (run once with Ollama serving or a real key before the demo).
func TestGenerateFixSectionFallback(t *testing.T) {
	finding := types.Finding{
		ID:       "a1b2c3d4",
		Title:    "SQL Injection",
		Severity: "HIGH",
		VulnType: scorer.TypeSQLi,
		Route:    types.Route{Method: "GET", Path: "/api/users"},
		Param:    "id",
		Location: "GET /api/users?id",
		Evidence: "response body contains \"syntax error\"",
	}

	client := NewLLMClient()
	client.Enabled = false // force the offline fallback path regardless of env

	section := GenerateFixSection(finding, client)

	for _, want := range []string{
		"## [🔴 HIGH] SQL Injection — GET /api/users",
		"**Location:** `GET /api/users?id`",
		"**Finding ID:** `a1b2c3d4`",
		"### Evidence",
		"response body contains \"syntax error\"",
		"### Root Cause",
		"### Suggested Fix",
		"### Acceptance Check",
		"Lain will re-scan this route on the next push to confirm remediation (finding ID `a1b2c3d4`)",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("fix section missing %q\n---section---\n%s", want, section)
		}
	}

	if !strings.Contains(section, "parameterized") {
		t.Errorf("expected fallback root cause for SQLi to mention parameterized queries:\n%s", section)
	}
	if !strings.Contains(section, "prepared statements") {
		t.Errorf("expected fallback fix for SQLi to mention prepared statements:\n%s", section)
	}
}

func TestGenerateFixSectionUnknownVulnType(t *testing.T) {
	finding := types.Finding{
		ID:       "deadbeef",
		Title:    "Mystery",
		Severity: "LOW",
		VulnType: "something-new",
		Route:    types.Route{Method: "GET", Path: "/new"},
		Location: "GET /new",
	}
	section := GenerateFixSection(finding, nil)
	if !strings.Contains(section, "### Root Cause") {
		t.Fatalf("expected a rendered section for unknown vuln type:\n%s", section)
	}
}

func TestWriteFixMD(t *testing.T) {
	result := types.ScanResult{
		Findings: []types.Finding{
			{
				ID:       "11111111",
				Title:    "Path Traversal",
				Severity: "HIGH",
				VulnType: scorer.TypePathTraversal,
				Route:    types.Route{Method: "GET", Path: "/files"},
				Param:    "name",
				Location: "GET /files?name",
				Evidence: "root:",
			},
		},
		TargetsScanned: 1,
	}

	path := filepath.Join(t.TempDir(), "fix.md")
	if err := WriteFixMD(result, nil, path); err != nil {
		t.Fatalf("WriteFixMD: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	md := string(data)

	for _, want := range []string{
		"# Lain Fix Report",
		"How to use this file",
		"## Summary",
		"1 finding(s), generated",
		"| `11111111` | 🔴 HIGH | Path Traversal | `GET /files?name` |",
		"## [🔴 HIGH] Path Traversal — GET /files",
		"### Suggested Fix",
		"filepath.Clean",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("fix report missing %q\n---report---\n%s", want, md)
		}
	}
}
