package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"lain/internal/types"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestSnapshotFromGitRef(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q", "-b", "main")
	runGit(t, repo, "config", "user.email", "lain@test")
	runGit(t, repo, "config", "user.name", "lain")

	write := func(version string) {
		t.Helper()
		content := `[{"method":"GET","path":"/api/users","params":["id"]}` + version + `]`
		if err := os.WriteFile(filepath.Join(repo, "routes.json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		runGit(t, repo, "add", "routes.json")
		runGit(t, repo, "commit", "-q", "-m", "v"+version)
	}

	write("")
	write(`,{"method":"GET","path":"/api/notes","params":["id"]}`)

	prevDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(prevDir) })
	if err := os.Chdir(repo); err != nil {
		t.Fatal(err)
	}

	head, err := SnapshotFromGitRef("HEAD", "routes.json")
	if err != nil {
		t.Fatalf("HEAD snapshot: %v", err)
	}
	base, err := SnapshotFromGitRef("HEAD~1", "routes.json")
	if err != nil {
		t.Fatalf("HEAD~1 snapshot: %v", err)
	}

	added, changed, unchanged := DiffRoutes(base, head)
	if len(added) != 1 || added[0].Path != "/api/notes" {
		t.Fatalf("added = %+v, want [/api/notes]", added)
	}
	if len(changed) != 0 || len(unchanged) != 1 {
		t.Fatalf("changed=%+v unchanged=%+v, want no changed and 1 unchanged", changed, unchanged)
	}

	if _, err := SnapshotFromGitRef("no-such-ref", "routes.json"); err == nil {
		t.Fatal("expected error for nonexistent ref, got nil")
	}
}

func TestDiffRoutes(t *testing.T) {
	base := []types.Route{
		{Method: "GET", Path: "/api/users", Params: []string{"id"}},
		{Method: "GET", Path: "/search", Params: []string{"q"}},
		{Method: "GET", Path: "/admin", Params: nil},
	}

	head := []types.Route{
		{Method: "GET", Path: "/api/users", Params: []string{"id", "fields"}},
		{Method: "GET", Path: "/search", Params: []string{"q"}},
		{Method: "GET", Path: "/admin", Params: nil},
		{Method: "GET", Path: "/api/notes", Params: []string{"id"}},
	}

	added, changed, unchanged := DiffRoutes(base, head)

	if len(added) != 1 || added[0].Path != "/api/notes" {
		t.Fatalf("added = %+v, want [/api/notes]", added)
	}

	if len(changed) != 1 || changed[0].Path != "/api/users" {
		t.Fatalf("changed = %+v, want [/api/users]", changed)
	}

	if len(unchanged) != 2 {
		t.Fatalf("unchanged = %+v, want 2 routes", unchanged)
	}
	wantUnchanged := []types.Route{
		{Method: "GET", Path: "/search", Params: []string{"q"}},
		{Method: "GET", Path: "/admin", Params: nil},
	}
	if !reflect.DeepEqual(unchanged, wantUnchanged) {
		t.Fatalf("unchanged = %+v, want %+v", unchanged, wantUnchanged)
	}
}

func TestDiffRoutesParamOrderInsensitive(t *testing.T) {
	base := []types.Route{{Method: "GET", Path: "/x", Params: []string{"a", "b"}}}
	head := []types.Route{{Method: "GET", Path: "/x", Params: []string{"b", "a"}}}

	added, changed, unchanged := DiffRoutes(base, head)
	if len(added) != 0 || len(changed) != 0 {
		t.Fatalf("same params in different order should be unchanged, got added=%+v changed=%+v", added, changed)
	}
	if len(unchanged) != 1 {
		t.Fatalf("unchanged = %+v, want 1 route", unchanged)
	}
}

func TestDiffRoutesBaseOnlyRoutesIgnored(t *testing.T) {
	base := []types.Route{
		{Method: "GET", Path: "/removed", Params: nil},
		{Method: "GET", Path: "/kept", Params: []string{"p"}},
	}
	head := []types.Route{{Method: "GET", Path: "/kept", Params: []string{"p"}}}

	added, changed, unchanged := DiffRoutes(base, head)
	if len(added) != 0 || len(changed) != 0 {
		t.Fatalf("expected no added/changed, got added=%+v changed=%+v", added, changed)
	}
	if len(unchanged) != 1 || unchanged[0].Path != "/kept" {
		t.Fatalf("unchanged = %+v, want [/kept]", unchanged)
	}
}
