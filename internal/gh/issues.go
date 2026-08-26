package gh

import (
	"fmt"
	"net/url"
	"strings"

	"lain/internal/types"
)

const (
	labelCategory = "lain"
	labelPrefix   = "lain:"
)

// Summary reports what a SyncIssues run did.
type Summary struct {
	Created     int
	Closed      int
	Rechecked   int
	CreatedURLs []string
}

type issue struct {
	Number  int     `json:"number"`
	Title   string  `json:"title"`
	Body    string  `json:"body"`
	State   string  `json:"state"`
	HTMLURL string  `json:"html_url"`
	Labels  []label `json:"labels"`
}

type label struct {
	Name string `json:"name"`
}

func findingLabel(id string) string { return labelPrefix + id }

func findingIDFromIssue(is issue) string {
	for _, l := range is.Labels {
		if strings.HasPrefix(l.Name, labelPrefix) {
			return strings.TrimPrefix(l.Name, labelPrefix)
		}
	}
	return ""
}

// SyncIssues reconciles GitHub issues with the current scan's findings:
//   - findings meeting minSeverity with no existing issue get an issue created;
//   - findings meeting minSeverity with an open issue are left open (rechecked);
//   - open lain issues whose finding no longer reproduces get closed.
//
// It is safe to run on every scan: it is idempotent, and issue identity is the
// stable finding ID (see scorer.GenerateFindingID).
func (c *Client) SyncIssues(findings []types.Finding, minSeverity string) (Summary, error) {
	var sum Summary

	present := make(map[string]bool)
	var tracked []types.Finding
	for _, f := range findings {
		if f.ID == "" || !SeverityAtLeast(f.Severity, minSeverity) {
			continue
		}
		present[f.ID] = true
		tracked = append(tracked, f)
	}

	for _, f := range tracked {
		label := findingLabel(f.ID)
		existing, err := c.findOpenIssueByLabel(label)
		if err != nil {
			return sum, fmt.Errorf("checking existing issue for %s: %w", label, err)
		}
		if existing != nil {
			sum.Rechecked++
			continue
		}
		url, err := c.createIssue(f)
		if err != nil {
			return sum, fmt.Errorf("creating issue for %s: %w", f.ID, err)
		}
		sum.Created++
		if url != "" {
			sum.CreatedURLs = append(sum.CreatedURLs, url)
		}
	}

	open, err := c.listOpenLabeledIssues(labelCategory)
	if err != nil {
		return sum, fmt.Errorf("listing open lain issues: %w", err)
	}
	for _, is := range open {
		id := findingIDFromIssue(is)
		if id != "" && !present[id] {
			if err := c.closeIssue(is.Number, id); err != nil {
				return sum, fmt.Errorf("closing issue #%d: %w", is.Number, err)
			}
			sum.Closed++
		}
	}

	return sum, nil
}

// findOpenIssueByLabel checks whether any open issue carries the exact label.
// It uses the issues-list endpoint rather than the search API because search
// rejects labels containing a colon (e.g. "lain:abc12345") with a 422, and the
// list endpoint is also free of the separate search rate limit.
func (c *Client) findOpenIssueByLabel(label string) (*issue, error) {
	path := fmt.Sprintf("/repos/%s/issues?state=open&labels=%s&per_page=1", c.Repo, url.QueryEscape(label))
	var issues []issue
	if _, err := c.do("GET", path, nil, &issues); err != nil {
		return nil, err
	}
	if len(issues) == 0 {
		return nil, nil
	}
	return &issues[0], nil
}

func (c *Client) listOpenLabeledIssues(label string) ([]issue, error) {
	path := fmt.Sprintf("/repos/%s/issues?state=open&labels=%s&per_page=100", c.Repo, label)
	var issues []issue
	if _, err := c.do("GET", path, nil, &issues); err != nil {
		return nil, err
	}
	return issues, nil
}

func (c *Client) createIssue(f types.Finding) (string, error) {
	payload := map[string]any{
		"title":  issueTitle(f),
		"body":   issueBody(f),
		"labels": []string{labelCategory, findingLabel(f.ID)},
	}
	var created issue
	if _, err := c.do("POST", fmt.Sprintf("/repos/%s/issues", c.Repo), payload, &created); err != nil {
		return "", err
	}
	return created.HTMLURL, nil
}

func (c *Client) closeIssue(number int, id string) error {
	if _, err := c.do("PATCH", fmt.Sprintf("/repos/%s/issues/%d", c.Repo, number), map[string]string{"state": "closed"}, nil); err != nil {
		return err
	}
	return c.comment(number, fmt.Sprintf(
		"Fixed — finding `%s` no longer reproduced in the latest scan. Closing automatically.", id))
}

func (c *Client) comment(number int, body string) error {
	payload := map[string]string{"body": body}
	_, err := c.do("POST", fmt.Sprintf("/repos/%s/issues/%d/comments", c.Repo, number), payload, nil)
	return err
}

func issueTitle(f types.Finding) string {
	return fmt.Sprintf("[lain] %s: %s — %s", f.Severity, f.Title, f.Location)
}

func issueBody(f types.Finding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("**Finding:** `%s` (%s)\n\n", f.ID, f.Severity))
	b.WriteString(fmt.Sprintf("**Vulnerability type:** `%s`\n\n", f.VulnType))
	b.WriteString(fmt.Sprintf("**Location:** `%s`\n\n", f.Location))
	if f.Param != "" {
		b.WriteString(fmt.Sprintf("**Parameter:** `%s`\n\n", f.Param))
	}
	if f.Payload != "" {
		b.WriteString(fmt.Sprintf("**Payload:**\n\n```\n%s\n```\n\n", f.Payload))
	}
	b.WriteString(fmt.Sprintf("**Evidence:**\n\n```\n%s\n```\n\n", f.Evidence))
	b.WriteString("---\n\n")
	b.WriteString("_Auto-generated by lain. This issue is closed automatically when the finding stops reproducing._\n")
	b.WriteString(fmt.Sprintf("<!-- lain-finding-id: %s -->\n", f.ID))
	return b.String()
}