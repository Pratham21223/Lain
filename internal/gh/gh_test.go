package gh

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"lain/internal/types"
)

type fakeGH struct {
	mu           sync.Mutex
	issues       map[int]issue
	comments     map[int][]issueComment
	patchComment map[int]string
	createBodies []map[string]any
	nextIssue    int
	nextComment  int
	authTokens   []string
}

func newFakeGH() *fakeGH {
	return &fakeGH{
		issues:       map[int]issue{},
		comments:     map[int][]issueComment{},
		patchComment: map[int]string{},
		nextIssue:    1,
		nextComment:  1,
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func decodeBody(w http.ResponseWriter, r *http.Request, out any) {
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (f *fakeGH) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/issues/comments/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authTokens = append(f.authTokens, r.Header.Get("Authorization"))
		f.mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id, _ := strconv.Atoi(parts[5])
		var body struct{ Body string }
		decodeBody(w, r, &body)
		f.mu.Lock()
		f.patchComment[id] = body.Body
		f.mu.Unlock()
		writeJSON(w, issueComment{ID: id, Body: body.Body})
	})
	mux.HandleFunc("/repos/owner/repo/issues/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authTokens = append(f.authTokens, r.Header.Get("Authorization"))
		f.mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		number, _ := strconv.Atoi(parts[4])
		if len(parts) == 6 && parts[5] == "comments" {
			f.handleIssueComments(w, r, number)
			return
		}
		f.handleIssue(w, r, number)
	})
	mux.HandleFunc("/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authTokens = append(f.authTokens, r.Header.Get("Authorization"))
		f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			label := r.URL.Query().Get("labels")
			var out []issue
			for _, is := range f.issues {
				if is.State != "open" {
					continue
				}
				if label != "" && !slices.Contains(issueLabelNames(is.Labels), label) {
					continue
				}
				out = append(out, is)
			}
			writeJSON(w, out)
		case http.MethodPost:
			var body map[string]any
			decodeBody(w, r, &body)
			iss := issue{
				Number:  f.nextIssue,
				State:   "open",
				Title:   body["title"].(string),
				HTMLURL: fmt.Sprintf("https://github.com/owner/repo/issues/%d", f.nextIssue),
			}
			for _, l := range body["labels"].([]any) {
				iss.Labels = append(iss.Labels, label{Name: l.(string)})
			}
			f.nextIssue++
			f.issues[iss.Number] = iss
			f.createBodies = append(f.createBodies, body)
			writeJSON(w, iss)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func issueLabelNames(labels []label) []string {
	var names []string
	for _, l := range labels {
		names = append(names, l.Name)
	}
	return names
}

func (f *fakeGH) handleIssue(w http.ResponseWriter, r *http.Request, number int) {
	var body struct{ State string }
	decodeBody(w, r, &body)
	f.mu.Lock()
	iss := f.issues[number]
	iss.State = body.State
	f.issues[number] = iss
	f.mu.Unlock()
	writeJSON(w, iss)
}

func (f *fakeGH) handleIssueComments(w http.ResponseWriter, r *http.Request, number int) {
	switch r.Method {
	case http.MethodGet:
		f.mu.Lock()
		out := append([]issueComment{}, f.comments[number]...)
		f.mu.Unlock()
		writeJSON(w, out)
	case http.MethodPost:
		var body struct{ Body string }
		decodeBody(w, r, &body)
		f.mu.Lock()
		c := issueComment{ID: f.nextComment, Body: body.Body}
		f.nextComment++
		f.comments[number] = append(f.comments[number], c)
		f.mu.Unlock()
		writeJSON(w, c)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func testClient(t *testing.T, f *fakeGH) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	t.Setenv("LAIN_GH_API", srv.URL)
	c := NewClient("test-token", "owner/repo")
	c.HTTP = srv.Client()
	return c
}

func sampleFinding(id, sev, loc string) types.Finding {
	return types.Finding{
		ID:       id,
		Title:    "SQL Injection",
		Severity: sev,
		VulnType: "sqli",
		Route:    types.Route{Method: "GET", Path: "/search", Params: []string{"q"}},
		Param:    "q",
		Payload:  "' OR '1'='1",
		Evidence: "HTTP 500 response",
		Location: loc,
	}
}

func TestSyncIssuesCreatesAndRechecks(t *testing.T) {
	f := newFakeGH()
	c := testClient(t, f)

	high := sampleFinding("aaa11111", "HIGH", "GET /admin/dashboard")
	medium := sampleFinding("bbb22222", "MEDIUM", "GET /profile?name")
	low := sampleFinding("ccc33333", "LOW", "GET /api/users")

	got, err := c.SyncIssues([]types.Finding{high, medium, low}, "MEDIUM")
	if err != nil {
		t.Fatalf("SyncIssues: %v", err)
	}
	if got.Created != 2 {
		t.Fatalf("created = %d, want 2", got.Created)
	}
	if got.Rechecked != 0 {
		t.Fatalf("rechecked = %d, want 0", got.Rechecked)
	}
	if got.Closed != 0 {
		t.Fatalf("closed = %d, want 0", got.Closed)
	}
	if len(got.CreatedURLs) != 2 || got.CreatedURLs[0] == "" {
		t.Fatalf("created URLs = %v, want 2 non-empty", got.CreatedURLs)
	}

	// Idempotent: re-running must not create again, just recheck.
	got, err = c.SyncIssues([]types.Finding{high, medium, low}, "MEDIUM")
	if err != nil {
		t.Fatalf("SyncIssues (2nd): %v", err)
	}
	if got.Created != 0 {
		t.Fatalf("created (2nd) = %d, want 0", got.Created)
	}
	if got.Rechecked != 2 {
		t.Fatalf("rechecked (2nd) = %d, want 2", got.Rechecked)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.createBodies) != 2 {
		t.Fatalf("created %d issues, want 2", len(f.createBodies))
	}
	labels := f.createBodies[0]["labels"].([]any)
	wantLabels := []string{"lain", "lain:aaa11111"}
	for i, wl := range wantLabels {
		if labels[i].(string) != wl {
			t.Errorf("label %d = %q, want %q", i, labels[i], wl)
		}
	}
	title, _ := f.createBodies[1]["title"].(string)
	if !strings.Contains(title, "MEDIUM") || !strings.Contains(title, "GET /profile?name") {
		t.Errorf("title = %q, want severity + location", title)
	}
}

func TestSyncIssuesClosesStale(t *testing.T) {
	f := newFakeGH()
	f.issues[1] = issue{Number: 1, State: "open", Labels: []label{{Name: "lain"}, {Name: "lain:deadbeef"}}}
	c := testClient(t, f)

	got, err := c.SyncIssues(nil, "MEDIUM")
	if err != nil {
		t.Fatalf("SyncIssues: %v", err)
	}
	if got.Closed != 1 {
		t.Fatalf("closed = %d, want 1", got.Closed)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues[1].State != "closed" {
		t.Errorf("issue 1 state = %q, want closed", f.issues[1].State)
	}
	if len(f.comments[1]) != 1 || !strings.Contains(f.comments[1][0].Body, "deadbeef") {
		t.Errorf("expected a 'Fixed' comment mentioning the finding ID, got %+v", f.comments[1])
	}
}

func TestSyncIssuesKeepsTrackedOpen(t *testing.T) {
	f := newFakeGH()
	f.issues[1] = issue{Number: 1, State: "open", Labels: []label{{Name: "lain"}, {Name: "lain:aaa11111"}}}
	c := testClient(t, f)

	got, err := c.SyncIssues([]types.Finding{sampleFinding("aaa11111", "HIGH", "GET /admin")}, "MEDIUM")
	if err != nil {
		t.Fatalf("SyncIssues: %v", err)
	}
	if got.Closed != 0 || got.Rechecked != 1 {
		t.Fatalf("closed = %d, rechecked = %d, want 0/1", got.Closed, got.Rechecked)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues[1].State != "open" {
		t.Errorf("issue 1 state = %q, want still open", f.issues[1].State)
	}
}

func TestSyncPRCommentCreateThenUpdate(t *testing.T) {
	f := newFakeGH()
	c := testClient(t, f)

	finding := sampleFinding("aaa11111", "HIGH", "GET /search?q")
	created, err := c.SyncPRComment(42, []types.Finding{finding}, "fix.md")
	if err != nil {
		t.Fatalf("SyncPRComment (create): %v", err)
	}
	if !created {
		t.Fatal("expected comment created on first run")
	}

	f.mu.Lock()
	first := append([]issueComment{}, f.comments[42]...)
	f.mu.Unlock()
	if len(first) != 1 {
		t.Fatalf("comments after create = %d, want 1", len(first))
	}
	if !strings.Contains(first[0].Body, prCommentMarker) {
		t.Error("created comment missing marker")
	}
	if !strings.Contains(first[0].Body, "HIGH") || !strings.Contains(first[0].Body, "GET /search?q") {
		t.Errorf("created comment missing findings table, got: %s", first[0].Body)
	}

	created, err = c.SyncPRComment(42, []types.Finding{}, "fix.md")
	if err != nil {
		t.Fatalf("SyncPRComment (update): %v", err)
	}
	if created {
		t.Fatal("expected update, not a new comment")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.comments[42]) != 1 {
		t.Fatalf("comments after update = %d, want still 1", len(f.comments[42]))
	}
	if body := f.patchComment[first[0].ID]; !strings.Contains(body, "no findings") {
		t.Errorf("updated comment body = %q, want 'no findings'", body)
	}
}

func TestAuthHeaderSent(t *testing.T) {
	f := newFakeGH()
	c := testClient(t, f)
	if _, err := c.SyncPRComment(1, nil, ""); err != nil {
		t.Fatalf("SyncPRComment: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.authTokens) == 0 || f.authTokens[0] != "Bearer test-token" {
		t.Errorf("auth header = %v, want Bearer test-token", f.authTokens)
	}
}

func TestResolvePRNumber(t *testing.T) {
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")
	t.Setenv("GITHUB_EVENT_PATH", "")
	if got := ResolvePRNumber(""); got != 123 {
		t.Fatalf("from GITHUB_REF = %d, want 123", got)
	}
	t.Setenv("GITHUB_REF", "")

	dir := t.TempDir()
	evPath := filepath.Join(dir, "event.json")
	os.WriteFile(evPath, []byte(`{"pull_request":{"number":456}}`), 0o600)
	t.Setenv("GITHUB_EVENT_PATH", evPath)
	if got := ResolvePRNumber(""); got != 456 {
		t.Fatalf("from GITHUB_EVENT_PATH = %d, want 456", got)
	}

	if got := ResolvePRNumber("42"); got != 42 {
		t.Fatalf("explicit = %d, want 42", got)
	}
}

func TestParseRemote(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://github.com/a/b.git", "a/b"},
		{"https://github.com/owner/repo", "owner/repo"},
		{"git@github.com:owner/repo.git", "owner/repo"},
		{"git://github.com/owner/repo.git", "owner/repo"},
		{"ssh://git@github.com/owner/repo.git", "owner/repo"},
	} {
		got, err := parseRemote(tc.in)
		if err != nil {
			t.Fatalf("parseRemote(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseRemote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAPIErrorIncludesBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Body:       io.NopCloser(strings.NewReader(`{"message":"Resource not accessible by integration","documentation_url":"https://docs.github.com/rest"}`)),
	}
	err := apiError("POST", "/repos/owner/repo/issues", resp)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error missing status: %v", err)
	}
	if !strings.Contains(err.Error(), "Resource not accessible") {
		t.Errorf("error missing GitHub message: %v", err)
	}
}

func TestSeverityAtLeast(t *testing.T) {
	for _, tc := range []struct {
		sev, min string
		want     bool
	}{
		{"HIGH", "MEDIUM", true},
		{"HIGH", "HIGH", true},
		{"MEDIUM", "HIGH", false},
		{"MEDIUM", "MEDIUM", true},
		{"LOW", "MEDIUM", false},
		{"LOW", "LOW", true},
	} {
		if got := SeverityAtLeast(tc.sev, tc.min); got != tc.want {
			t.Errorf("SeverityAtLeast(%s, %s) = %v, want %v", tc.sev, tc.min, got, tc.want)
		}
	}
}