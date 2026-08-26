package bruteforce

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBruteForce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/api", "/login":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wordlist := []string{"admin", "api", "login", "doesnotexist1", "doesnotexist2"}
	routes := BruteForce(server.URL, wordlist, server.Client(), 3)

	if len(routes) != 3 {
		t.Fatalf("expected 3 discovered routes, got %d: %v", len(routes), routes)
	}

	found := make(map[string]bool)
	for _, r := range routes {
		if r.Method != "GET" {
			t.Errorf("route %s: expected Method GET, got %s", r.Path, r.Method)
		}
		if len(r.Params) != 0 {
			t.Errorf("route %s: expected empty params, got %v", r.Path, r.Params)
		}
		found[r.Path] = true
	}

	for _, p := range []string{"/admin", "/api", "/login"} {
		if !found[p] {
			t.Errorf("expected to discover route %s", p)
		}
	}
}
