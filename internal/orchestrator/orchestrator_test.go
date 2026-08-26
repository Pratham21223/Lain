package orchestrator

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"lain/internal/config"
	"lain/internal/types"
)

func newVulnServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users":
			id := r.URL.Query().Get("id")
			if _, err := strconv.Atoi(id); err != nil {
				http.Error(w, "near \""+id+"\": syntax error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"id":1}]`)
		case "/search":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body><h1>Search results for: %s</h1></body></html>", r.URL.Query().Get("q"))
		default:
			http.NotFound(w, r)
		}
	}))
}

func newSlowServer(delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
}

func TestRunScanAggregatesResults(t *testing.T) {
	server := newVulnServer()
	defer server.Close()

	routes := []types.Route{
		{Method: "GET", Path: "/api/users", Params: []string{"id"}},
		{Method: "GET", Path: "/search", Params: []string{"q"}},
		{Method: "GET", Path: "/missing", Params: []string{"x"}},
	}

	cfg := config.Default()
	cfg.TargetURL = server.URL
	cfg.Concurrency = 4

	res := RunScan(cfg, routes)

	if res.TargetsScanned != len(routes) {
		t.Errorf("TargetsScanned = %d, want %d", res.TargetsScanned, len(routes))
	}
	if res.StartedAt.IsZero() || res.FinishedAt.IsZero() {
		t.Errorf("expected StartedAt and FinishedAt to be set")
	}
	if !res.FinishedAt.After(res.StartedAt) {
		t.Errorf("FinishedAt (%v) should be after StartedAt (%v)", res.FinishedAt, res.StartedAt)
	}

	titles := make(map[string]bool)
	for _, f := range res.Findings {
		titles[f.Title] = true
	}
	if !titles["SQL Injection"] {
		t.Errorf("missing SQL Injection finding, got: %v", titles)
	}
	if !titles["Reflected XSS"] {
		t.Errorf("missing Reflected XSS finding, got: %v", titles)
	}
}

func TestRunScanConcurrencySpeedup(t *testing.T) {
	server := newSlowServer(50 * time.Millisecond)
	defer server.Close()

	routes := []types.Route{
		{Method: "GET", Path: "/r1", Params: []string{"p"}},
		{Method: "GET", Path: "/r2", Params: []string{"p"}},
		{Method: "GET", Path: "/r3", Params: []string{"p"}},
		{Method: "GET", Path: "/r4", Params: []string{"p"}},
	}

	cfg := config.Default()
	cfg.TargetURL = server.URL

	cfg1 := cfg
	cfg1.Concurrency = 1

	cfg10 := cfg
	cfg10.Concurrency = 10

	start := time.Now()
	res1 := RunScan(cfg1, routes)
	el1 := time.Since(start)

	start = time.Now()
	res10 := RunScan(cfg10, routes)
	el10 := time.Since(start)

	t.Logf("concurrency=1 : %v (%d targets)", el1, res1.TargetsScanned)
	t.Logf("concurrency=10: %v (%d targets)", el10, res10.TargetsScanned)
	t.Logf("speedup: %.1fx", float64(el1)/float64(el10))

	if el1 <= el10 {
		t.Errorf("expected concurrency=1 (%v) to be slower than concurrency=10 (%v)", el1, el10)
	}
	if el10 > el1/2 {
		t.Errorf("concurrency=10 (%v) should be at least 2x faster than concurrency=1 (%v)", el10, el1)
	}
}

func BenchmarkRunScanConcurrency(b *testing.B) {
	server := newSlowServer(30 * time.Millisecond)
	defer server.Close()

	routes := make([]types.Route, 8)
	for i := range routes {
		routes[i] = types.Route{Method: "GET", Path: fmt.Sprintf("/r%d", i+1), Params: []string{"p"}}
	}

	for _, c := range []int{1, 10} {
		cfg := config.Default()
		cfg.TargetURL = server.URL
		cfg.Concurrency = c
		b.Run(fmt.Sprintf("workers-%d", c), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				RunScan(cfg, routes)
			}
		})
	}
}
