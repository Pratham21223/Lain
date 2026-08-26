package scorer

import (
	"testing"

	"lain/internal/types"
)

func TestSeverity(t *testing.T) {
	cases := map[string]string{
		TypeSQLi:          "HIGH",
		TypePathTraversal: "HIGH",
		TypeUnauthRoute:   "HIGH",
		TypeXSS:           "MEDIUM",
		"unknown":         "LOW",
	}
	for vulnType, want := range cases {
		if got := Severity(vulnType); got != want {
			t.Errorf("Severity(%q) = %q, want %q", vulnType, got, want)
		}
	}
}

func TestGenerateFindingIDStable(t *testing.T) {
	base := types.Finding{
		Route:    types.Route{Method: "GET", Path: "/api/users"},
		Param:    "id",
		VulnType: TypeSQLi,
	}

	first := GenerateFindingID(base)
	second := GenerateFindingID(base)
	if first != second {
		t.Fatalf("same finding produced different IDs: %q vs %q", first, second)
	}
	if len(first) != 8 {
		t.Errorf("expected 8 hex chars, got %q", first)
	}

	sameBugDifferentPayload := base
	sameBugDifferentPayload.Payload = "' UNION SELECT NULL--"
	if got := GenerateFindingID(sameBugDifferentPayload); got != first {
		t.Errorf("payload change should not change ID: got %q, want %q", got, first)
	}

	differentVulnType := base
	differentVulnType.VulnType = TypeXSS
	if got := GenerateFindingID(differentVulnType); got == first {
		t.Error("different vuln type should produce a different ID")
	}

	differentParam := base
	differentParam.Param = "q"
	if got := GenerateFindingID(differentParam); got == first {
		t.Error("different param should produce a different ID")
	}
}

func TestDeduplicate(t *testing.T) {
	mk := func(id, evidence string) types.Finding {
		return types.Finding{ID: id, Evidence: evidence}
	}

	findings := []types.Finding{
		mk("aaaa", "evidence-1"),
		mk("aaaa", "evidence-2"),
		mk("bbbb", "evidence-3"),
		mk("aaaa", "evidence-4"),
		mk("cccc", "evidence-5"),
	}

	dedup := Deduplicate(findings)

	if len(dedup) != 3 {
		t.Fatalf("len = %d, want 3: %+v", len(dedup), dedup)
	}
	if dedup[0].ID != "aaaa" || dedup[0].Evidence != "evidence-1" {
		t.Errorf("first duplicate should keep first evidence, got %+v", dedup[0])
	}
	if dedup[1].ID != "bbbb" || dedup[2].ID != "cccc" {
		t.Errorf("distinct findings should be preserved in order, got %+v", dedup)
	}

	noID := Deduplicate([]types.Finding{mk("", "x"), mk("", "y")})
	if len(noID) != 2 {
		t.Errorf("findings without ID should not be collapsed, got %+v", noID)
	}
}
