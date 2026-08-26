package gh

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"lain/internal/types"
)

// prCommentMarker anchors lain's comment so it can be found and updated in
// place instead of posting a fresh comment on every scan.
const prCommentMarker = "<!-- lain-comment -->"

// ResolvePRNumber determines the pull request number from an explicit value or
// CI environment (GITHUB_REF, then GITHUB_EVENT_PATH). Returns 0 when no PR
// context exists.
func ResolvePRNumber(explicit string) int {
	if explicit != "" {
		var n int
		if _, err := fmt.Sscanf(explicit, "%d", &n); err == nil {
			return n
		}
	}
	if ref := os.Getenv("GITHUB_REF"); ref != "" {
		var n int
		if _, err := fmt.Sscanf(ref, "refs/pull/%d/", &n); err == nil {
			return n
		}
	}
	if path := os.Getenv("GITHUB_EVENT_PATH"); path != "" {
		if n := prNumberFromEvent(path); n > 0 {
			return n
		}
	}
	return 0
}

func prNumberFromEvent(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var ev struct {
		Number      int `json:"number"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return 0
	}
	if ev.PullRequest.Number > 0 {
		return ev.PullRequest.Number
	}
	return ev.Number
}

type issueComment struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

// SyncPRComment posts the scan summary to a pull request, updating a single
// self-anchored comment in place across pushes. Returns true when the comment
// was created, false when it was updated.
func (c *Client) SyncPRComment(prNumber int, findings []types.Finding, fixPath string) (bool, error) {
	body := prCommentBody(findings, fixPath)
	existing, err := c.findPRComment(prNumber)
	if err != nil {
		return false, err
	}
	if existing != nil {
		if _, err := c.do("PATCH", fmt.Sprintf("/repos/%s/issues/comments/%d", c.Repo, existing.ID), map[string]string{"body": body}, nil); err != nil {
			return false, err
		}
		return false, nil
	}
	if _, err := c.do("POST", fmt.Sprintf("/repos/%s/issues/%d/comments", c.Repo, prNumber), map[string]string{"body": body}, nil); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) findPRComment(prNumber int) (*issueComment, error) {
	path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100", c.Repo, prNumber)
	var comments []issueComment
	if _, err := c.do("GET", path, nil, &comments); err != nil {
		return nil, err
	}
	for i := range comments {
		if strings.Contains(comments[i].Body, prCommentMarker) {
			return &comments[i], nil
		}
	}
	return nil, nil
}

func prCommentBody(findings []types.Finding, fixPath string) string {
	var b strings.Builder

	if len(findings) == 0 {
		b.WriteString("## ✅ Lain scan: no findings\n\n")
		b.WriteString(prCommentMarker)
		return b.String()
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	b.WriteString("## 🔍 Lain scan results\n\n")
	b.WriteString(fmt.Sprintf("**%d finding(s)** — HIGH: %d, MEDIUM: %d, LOW: %d\n\n",
		len(findings), counts["HIGH"], counts["MEDIUM"], counts["LOW"]))
	b.WriteString("| Severity | Finding | Location | Evidence |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, f := range findings {
		ev := strings.ReplaceAll(f.Evidence, "\n", " ")
		if len(ev) > 60 {
			ev = ev[:60] + "…"
		}
		row := []string{
			f.Severity,
			strings.ReplaceAll(f.Title, "|", "\\|"),
			"`" + strings.ReplaceAll(f.Location, "|", "\\|") + "`",
			strings.ReplaceAll(ev, "|", "\\|"),
		}
		b.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}
	if fixPath != "" {
		b.WriteString(fmt.Sprintf("\n_Full report and remediation: see the `%s` artifact._\n", fixPath))
	}
	b.WriteString("\n")
	b.WriteString(prCommentMarker)
	return b.String()
}