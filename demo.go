package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// demoMain runs the one-command demo: make sure the vulnerable app is up, scan
// it (by re-invoking this same binary with scan flags), open the dashboard, and
// stop the app. Being part of the Go binary, it works on any OS.
func demoMain(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	target := fs.String("target", "http://127.0.0.1:5000", "base URL of the app to scan")
	appDir := fs.String("app-dir", "", "path to the app directory (default: auto-detect ../vulnbank- or ./vulnbank-)")
	keepRunning := fs.Bool("keep-running", false, "leave the app running after the scan")
	noOpen := fs.Bool("no-open", false, "do not open the dashboard in a browser")
	useLLM := fs.Bool("llm", false, "use the configured LLM for fix generation (LAIN_LLM_* env)")
	repo := fs.String("repo", "", "owner/repo to auto-file GitHub issues for findings")
	token := fs.String("token", "", "GitHub token (env GITHUB_TOKEN / LAIN_GH_TOKEN accepted)")
	fs.Parse(args)

	*target = strings.TrimRight(*target, "/")
	dir, err := resolveAppDir(*appDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("=== lain demo ===")
	fmt.Println("app dir :", dir)
	fmt.Println("target  :", *target)
	if *repo != "" {
		fmt.Println("github  :", *repo)
	}

	proc, started, err := ensureAppUp(*target, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}

	exe, err := os.Executable()
	if err != nil {
		stopApp(proc)
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}

	scanArgs := []string{"--target", *target, "--routes", filepath.Join(dir, "routes.json")}
	if !*useLLM {
		scanArgs = append(scanArgs, "--skip-llm")
	}
	tok := *token
	if tok == "" {
		tok = firstNonEmpty(os.Getenv("LAIN_GH_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	}
	if tok != "" {
		scanArgs = append(scanArgs, "--gh-token", tok)
	}
	if *repo != "" {
		scanArgs = append(scanArgs, "--gh-repo", *repo)
	}

	fmt.Println()
	cmd := exec.Command(exe, scanArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	scanErr := cmd.Run()

	exit := 0
	if scanErr != nil {
		if ee, ok := scanErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			fmt.Fprintln(os.Stderr, "demo: failed to run the scan:", scanErr)
			exit = 1
		}
	}

	if !*noOpen {
		if html := filepath.Join(".", "report.html"); fileExists(html) {
			openInBrowser(html)
		}
	}

	if started && !*keepRunning {
		stopApp(proc)
	}

	os.Exit(exit)
}

func resolveAppDir(explicit string) (string, error) {
	if explicit != "" {
		if fi, err := os.Stat(explicit); err != nil || !fi.IsDir() {
			return "", fmt.Errorf("app dir %q not found", explicit)
		}
		if !fileExists(filepath.Join(explicit, "app.py")) {
			return "", fmt.Errorf("app dir %q has no app.py", explicit)
		}
		return explicit, nil
	}
	cwd, _ := os.Getwd()
	// Search the current directory upward (up to 8 levels) for a vulnbank- app,
	// so `lain` works from anywhere inside the project repo, not just the root.
	for depth, d := 0, cwd; depth < 8; depth++ {
		cand := filepath.Join(d, "vulnbank-")
		if fileExists(filepath.Join(cand, "app.py")) {
			return cand, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return "", fmt.Errorf("could not find the app directory; pass --app-dir <path>")
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func appUp(healthURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ensureAppUp returns a running app process (nil if it was already up) along
// with whether demo started it.
func ensureAppUp(target, appDir string) (*exec.Cmd, bool, error) {
	health := target + "/health"
	if appUp(health) {
		return nil, false, nil
	}

	py := "python"
	if _, err := exec.LookPath("python"); err != nil {
		py = "python3"
	}
	cmd := exec.Command(py, "app.py")
	cmd.Dir = appDir
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("starting %s app.py: %w", py, err)
	}

	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if appUp(health) {
			return cmd, true, nil
		}
	}
	stopApp(cmd)
	return nil, false, fmt.Errorf("app did not become healthy at %s", health)
}

func stopApp(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func openInBrowser(path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	case "darwin":
		cmd = exec.Command("open", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "demo: could not open the browser; report at", abs)
	}
}