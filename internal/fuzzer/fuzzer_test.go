package fuzzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lain/internal/types"
)

type mockUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

// simulateUsersQuery mirrors the observable behavior of vulnapp's /api/users,
// which builds "SELECT ... FROM users WHERE id = " + id with no parameterization.
func simulateUsersQuery(id string) (int, string) {
	expr := strings.ToLower(strings.TrimSpace(id))
	if i := strings.Index(expr, "--"); i >= 0 {
		expr = strings.TrimSpace(expr[:i])
	}
	if i := strings.Index(expr, ";"); i >= 0 {
		expr = strings.TrimSpace(expr[:i])
	}

	if n, err := strconv.Atoi(expr); err == nil {
		if n >= 1 && n <= 4 {
			u := mockUser{ID: n, Username: fmt.Sprintf("user%d", n), Password: "pw", IsAdmin: n == 4}
			b, _ := json.Marshal([]mockUser{u})
			return http.StatusOK, string(b)
		}
		return http.StatusOK, `[]`
	}

	if strings.Contains(expr, "union") {
		return http.StatusInternalServerError, "sqlite3: SELECTs to the left and right of UNION do not have the same number of result columns"
	}

	if strings.Contains(expr, " and ") {
		parts := strings.SplitN(expr, " and ", 2)
		left, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err == nil && left >= 1 && left <= 4 {
			right := strings.TrimSpace(parts[1])
			if sides := strings.SplitN(right, "=", 2); len(sides) == 2 {
				a, errA := strconv.Atoi(strings.TrimSpace(sides[0]))
				b, errB := strconv.Atoi(strings.TrimSpace(sides[1]))
				if errA == nil && errB == nil && a == b {
					u := mockUser{ID: left, Username: fmt.Sprintf("user%d", left), Password: "pw", IsAdmin: left == 4}
					bj, _ := json.Marshal([]mockUser{u})
					return http.StatusOK, string(bj)
				}
				return http.StatusOK, `[]`
			}
		}
		return http.StatusInternalServerError, fmt.Sprintf("sqlite3: near %q: syntax error", id)
	}

	return http.StatusInternalServerError, fmt.Sprintf("sqlite3: near %q: syntax error", id)
}

func newMockServer(dataDir string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users":
			status, body := simulateUsersQuery(r.URL.Query().Get("id"))
			if status != http.StatusOK {
				http.Error(w, body, status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
		case "/search":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body><h1>Search results for: %s</h1></body></html>", r.URL.Query().Get("q"))
		case "/admin":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"secrets":[{"flag":"flag{test-lain}","note":"fake admin secret"}]}`)
		case "/files":
			name := r.URL.Query().Get("name")
			path := filepath.Join(dataDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestFuzzRouteFindsVulns(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "notes.txt"), []byte("hello notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	server := newMockServer(dataDir)
	defer server.Close()

	routes := []types.Route{
		{Method: "GET", Path: "/api/users", Params: []string{"id"}},
		{Method: "GET", Path: "/search", Params: []string{"q"}},
		{Method: "GET", Path: "/files", Params: []string{"name"}},
		{Method: "GET", Path: "/admin", Params: nil},
	}

	var findings []types.Finding
	for _, r := range routes {
		findings = append(findings, FuzzRoute(server.URL, r, server.Client())...)
	}

	byLocation := make(map[string]types.Finding)
	for _, f := range findings {
		t.Logf("finding: %s | %s | %s | payload=%q | evidence=%s", f.Location, f.Severity, f.Title, f.Payload, f.Evidence)
		byLocation[f.Location] = f
	}

	check := func(loc string, wantTitle, wantSeverity string, wantPayload bool) {
		f, ok := byLocation[loc]
		if !ok {
			t.Errorf("missing finding at %s (want %s/%s)", loc, wantTitle, wantSeverity)
			return
		}
		if f.Title != wantTitle {
			t.Errorf("finding at %s: title = %q, want %q", loc, f.Title, wantTitle)
		}
		if f.Severity != wantSeverity {
			t.Errorf("finding at %s: severity = %q, want %q", loc, f.Severity, wantSeverity)
		}
		if f.Evidence == "" {
			t.Errorf("finding at %s: expected non-empty evidence", loc)
		}
		if wantPayload && f.Payload == "" {
			t.Errorf("finding at %s: expected non-empty payload", loc)
		}
	}

	check("GET /api/users?id", "SQL Injection", "HIGH", true)
	check("GET /search?q", "Reflected XSS", "MEDIUM", true)
	check("GET /files?name", "Path Traversal", "HIGH", true)
	check("GET /admin", "Unauthenticated sensitive route", "HIGH", false)

	if f, ok := byLocation["GET /search?q"]; ok && strings.Contains(f.Title, "SQL") {
		t.Errorf("false positive: SQL finding on /search: %s (%s)", f.Title, f.Evidence)
	}
	if f, ok := byLocation["GET /api/users?id"]; ok && strings.Contains(f.Title, "XSS") {
		t.Errorf("false positive: XSS finding on /api/users: %s (%s)", f.Title, f.Evidence)
	}
}
