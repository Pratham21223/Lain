package gh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://api.github.com"
	userAgent      = "lain"
)

// Client is a minimal hand-rolled GitHub REST client. It intentionally has no
// external dependencies so lain stays dependency-light.
type Client struct {
	BaseURL string
	Token   string
	Repo    string
	HTTP    *http.Client
}

// NewClient builds a client. If repo is empty it is resolved from the
// environment (GITHUB_REPOSITORY) and then the origin remote of the current
// git repository. LAIN_GH_API overrides the API base URL (used by tests).
func NewClient(token, repo string) *Client {
	base := os.Getenv("LAIN_GH_API")
	if base == "" {
		base = DefaultBaseURL
	}
	c := &Client{
		BaseURL: strings.TrimRight(base, "/"),
		Token:   token,
		Repo:    repo,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
	if c.Repo == "" {
		if r, err := ResolveRepo(""); err == nil {
			c.Repo = r
		}
	}
	return c
}

// Enabled reports whether issue/PR automation can run at all.
func (c *Client) Enabled() bool {
	return c.Token != "" && c.Repo != ""
}

func severityRank(sev string) int {
	switch sev {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	default:
		return 1
	}
}

// SeverityAtLeast reports whether a finding's severity meets a minimum.
func SeverityAtLeast(severity, min string) bool {
	return severityRank(severity) >= severityRank(min)
}

// ResolveRepo returns "owner/repo", preferring an explicit value, then
// GITHUB_REPOSITORY (CI), then the origin remote of the current git repo.
func ResolveRepo(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv("GITHUB_REPOSITORY"); env != "" {
		return env, nil
	}
	url, err := remoteURL()
	if err != nil {
		return "", err
	}
	return parseRemote(url)
}

func remoteURL() (string, error) {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return "", fmt.Errorf("resolve github repo: %w (pass --gh-repo or set GITHUB_REPOSITORY)", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func parseRemote(url string) (string, error) {
	url = strings.TrimSuffix(url, ".git")
	switch {
	case strings.HasPrefix(url, "https://github.com/"):
		return strings.TrimPrefix(url, "https://github.com/"), nil
	case strings.HasPrefix(url, "git@github.com:"):
		return strings.TrimPrefix(url, "git@github.com:"), nil
	case strings.HasPrefix(url, "git://github.com/"):
		return strings.TrimPrefix(url, "git://github.com/"), nil
	case strings.HasPrefix(url, "ssh://git@github.com/"):
		return strings.TrimPrefix(url, "ssh://git@github.com/"), nil
	default:
		return "", fmt.Errorf("unsupported git remote %q: expected a github.com URL", url)
	}
}

// do performs an authenticated JSON request and decodes the response into out
// (when out is non-nil and the status is not 204). Non-2xx responses return an
// error carrying the status line.
func (c *Client) do(method, path string, body any, out any) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, c.BaseURL+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return resp, apiError(method, path, resp)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// apiError builds an error that includes GitHub's JSON message so the reason a
// call failed (missing permission, nonexistent repo, rate limit, ...) is never
// a guessing game.
func apiError(method, path string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(body))
	if msg != "" {
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return fmt.Errorf("github api %s %s: %s: %s", method, path, resp.Status, msg)
	}
	return fmt.Errorf("github api %s %s: %s", method, path, resp.Status)
}