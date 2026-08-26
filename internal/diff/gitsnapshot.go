package diff

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"lain/internal/types"
)

// SnapshotFromGitRef loads routes.json as it exists at the given git ref
// (branch, tag, or commit hash) via `git show <ref>:<path>`. The routesPath is
// resolved relative to the current repository root, so it works whether it is
// given as a repo-relative path ("routes.json") or as a filesystem path that
// happens to live inside the repo ("../vulnapp/routes.json").
func SnapshotFromGitRef(ref string, routesPath string) ([]types.Route, error) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return nil, fmt.Errorf("not inside a git repository: %w", err)
	}

	abs, err := filepath.Abs(routesPath)
	if err != nil {
		return nil, fmt.Errorf("resolving routes path %q: %w", routesPath, err)
	}
	rel, err := filepath.Rel(strings.TrimSpace(string(top)), abs)
	if err != nil {
		return nil, fmt.Errorf("routes path %q outside repository: %w", routesPath, err)
	}
	gitPath := filepath.ToSlash(rel)

	out, err := exec.Command("git", "show", ref+":"+gitPath).Output()
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %w", ref, gitPath, err)
	}

	tmp, err := os.CreateTemp("", "lain-snapshot-*.json")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(bytes.TrimSpace(out)); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing temp snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing temp snapshot: %w", err)
	}

	routes, err := LoadSnapshot(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("loading snapshot %s@%s: %w", routesPath, ref, err)
	}
	return routes, nil
}
