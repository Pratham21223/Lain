package scorer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"lain/internal/types"
)

const (
	TypeSQLi          = "sqli"
	TypeXSS           = "xss"
	TypePathTraversal = "pathtraversal"
	TypeUnauthRoute   = "unauthroute"
)

var severityByVulnType = map[string]string{
	TypeSQLi:          "HIGH",
	TypePathTraversal: "HIGH",
	TypeUnauthRoute:   "HIGH",
	TypeXSS:           "MEDIUM",
}

func Severity(vulnType string) string {
	if s, ok := severityByVulnType[vulnType]; ok {
		return s
	}
	return "LOW"
}

// GenerateFindingID returns a short stable hash identifying the underlying bug:
// the same route + param + vuln type always maps to the same ID across scans,
// independent of the payload that triggered it.
func GenerateFindingID(f types.Finding) string {
	seed := strings.Join([]string{f.Route.Method, f.Route.Path, f.Param, f.VulnType}, "|")
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])[:8]
}

// Deduplicate collapses findings sharing the same ID, keeping the first
// occurrence (and thus its evidence). Findings without an ID are always kept.
func Deduplicate(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool, len(findings))
	dedup := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		if f.ID != "" && seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		dedup = append(dedup, f)
	}
	return dedup
}
