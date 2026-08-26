package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"lain/internal/bruteforce"
	"lain/internal/config"
	"lain/internal/diff"
	"lain/internal/fixgen"
	"lain/internal/gh"
	"lain/internal/loader"
	"lain/internal/orchestrator"
	"lain/internal/report"
	"lain/internal/types"
	"lain/internal/ui"
)

func main() {
	// Bare "lain" or "lain demo" runs the one-command demo (works on any OS);
	// any other invocation is the normal flag-driven scan.
	if len(os.Args) == 1 {
		demoMain(nil)
		return
	}
	if os.Args[1] == "demo" {
		demoMain(os.Args[2:])
		return
	}

	noColor := flag.Bool("no-color", false, "disable ANSI colors in output")
	target := flag.String("target", "http://localhost:3000", "base URL of the app to scan")
	routesFile := flag.String("routes", "./routes.json", "path to routes.json")
	concurrency := flag.Int("concurrency", 10, "number of concurrent scan workers")
	bruteForce := flag.Bool("bruteforce", true, "also run the directory brute-forcer")
	baseRef := flag.String("base-ref", "", "git ref to diff routes against (empty = scan all routes)")
	reportJSON := flag.String("report-json", "report.json", "output path for the SARIF report")
	reportMD := flag.String("report-md", "report.md", "output path for the markdown report")
	reportHTML := flag.String("report-html", "report.html", "output path for the HTML dashboard")
	fixOut := flag.String("fix-out", "fix.md", "output path for the fix report")
	skipLLM := flag.Bool("skip-llm", false, "force the fallback fix template even if an LLM is configured")
	ghToken := flag.String("gh-token", "", "GitHub token for issue/PR automation (env GITHUB_TOKEN or LAIN_GH_TOKEN)")
	ghRepo := flag.String("gh-repo", "", "owner/repo to sync against (env GITHUB_REPOSITORY, else git origin)")
	ghMinSeverity := flag.String("gh-min-severity", "MEDIUM", "minimum severity (HIGH/MEDIUM/LOW) to auto-file issues")
	prNumber := flag.String("pr-number", "", "pull request number to post the scan summary to (auto-detected in CI)")
	flag.Parse()

	u := ui.New(*noColor, os.Stdout)
	u.Banner()

	cfg := config.Default()
	cfg.TargetURL = *target
	cfg.RoutesFile = *routesFile
	cfg.Concurrency = *concurrency

	head, err := loader.LoadRoutes(*routesFile)
	if err != nil {
		if *bruteForce && os.IsNotExist(err) {
			head = nil
		} else {
			u.Error("failed to load routes: %v", err)
			os.Exit(1)
		}
	}

	var scanRoutes []types.Route
	if *baseRef != "" {
		base, err := diff.SnapshotFromGitRef(*baseRef, *routesFile)
		if err != nil {
			u.Error("failed to load base snapshot: %v", err)
			os.Exit(1)
		}
		added, changed, unchanged := diff.DiffRoutes(base, head)
		scanRoutes = append(scanRoutes, added...)
		scanRoutes = append(scanRoutes, changed...)
		u.Info("Diff mode (%s): %d new route(s), %d changed route(s), %d unchanged (skipped)",
			*baseRef, len(added), len(changed), len(unchanged))
	} else {
		scanRoutes = head
		u.Info("Full scan mode: %d loaded route(s), no --base-ref diff", len(scanRoutes))
	}

	if *bruteForce {
		knownCount := len(scanRoutes)
		httpClient := &http.Client{Timeout: cfg.Timeout}
		discovered := bruteforce.BruteForce(cfg.TargetURL, bruteforce.DefaultWordlist, httpClient, cfg.Concurrency)
		scanRoutes = mergeRoutes(scanRoutes, discovered)
		u.Info("brute-force: discovered %d new route(s)", len(scanRoutes)-knownCount)
	}

	u.Info("scanning %d route(s) against %s", len(scanRoutes), cfg.TargetURL)
	u.Info("")

	result := orchestrator.RunScanWithProgress(cfg, scanRoutes, func(p orchestrator.Progress) {
		u.Progress(p.Done, p.Total, p.Route.Method, p.Route.Path, p.Findings)
	})
	u.EndProgress()

	if err := report.WriteSarifJSON(report.ToSarif(result), *reportJSON); err != nil {
		u.Error("failed to write SARIF report: %v", err)
	}
	if err := report.WriteMarkdownReport(result, *reportMD); err != nil {
		u.Error("failed to write markdown report: %v", err)
	}
	if err := report.WriteHTMLReport(result, cfg.TargetURL, firstNonEmpty(*ghRepo, os.Getenv("GITHUB_REPOSITORY")), *reportHTML); err != nil {
		u.Error("failed to write HTML report: %v", err)
	}

	llmClient := fixgen.NewLLMClient()
	if *skipLLM {
		llmClient.Enabled = false
	}
	if err := fixgen.WriteFixMD(result, llmClient, *fixOut); err != nil {
		u.Error("failed to write fix report: %v", err)
	}

	if err := syncGitHub(u, result, *ghToken, *ghRepo, *ghMinSeverity, *prNumber, *fixOut); err != nil {
		u.Error("%v", err)
	}

	if len(result.Findings) > 0 {
		u.Info("")
		u.Findings(result.Findings)
	}

	u.Summary(result, []string{*reportJSON, *reportMD, *reportHTML, *fixOut})

	if high := countHigh(result.Findings); high > 0 {
		u.Fail(high)
		os.Exit(1)
	}
	u.Pass()
}

func mergeRoutes(known, discovered []types.Route) []types.Route {
	seen := make(map[string]bool)
	merged := make([]types.Route, 0, len(known)+len(discovered))
	for _, list := range [][]types.Route{known, discovered} {
		for _, r := range list {
			key := r.Method + " " + r.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, r)
		}
	}
	return merged
}

func countHigh(findings []types.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Severity == "HIGH" {
			n++
		}
	}
	return n
}

// syncGitHub auto-files issues for findings and posts the scan summary to a PR
// when GitHub credentials and context are available. It degrades gracefully:
// without a token (offline demo), it is a no-op.
func syncGitHub(u *ui.UI, result types.ScanResult, token, repo, minSeverity, prNumber, fixOut string) error {
	token = firstNonEmpty(token, os.Getenv("LAIN_GH_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		u.Info("github: skipped — no token (pass --gh-token or set GITHUB_TOKEN)")
		return nil
	}

	client := gh.NewClient(token, repo)
	if !client.Enabled() {
		u.Info("github: skipped — no repository resolved (pass --gh-repo or set GITHUB_REPOSITORY)")
		return nil
	}

	summary, err := client.SyncIssues(result.Findings, minSeverity)
	if err != nil {
		return fmt.Errorf("github issue sync: %v", err)
	}
	u.Info("github: %d issue(s) created, %d closed, %d rechecked",
		summary.Created, summary.Closed, summary.Rechecked)
	for _, url := range summary.CreatedURLs {
		u.Info("  → %s", url)
	}

	if pr := gh.ResolvePRNumber(prNumber); pr > 0 {
		created, err := client.SyncPRComment(pr, result.Findings, fixOut)
		if err != nil {
			return fmt.Errorf("github pr comment: %v", err)
		}
		if created {
			u.Info("github: posted scan summary to PR #%d", pr)
		} else {
			u.Info("github: updated scan summary on PR #%d", pr)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
