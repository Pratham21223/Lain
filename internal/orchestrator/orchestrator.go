package orchestrator

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lain/internal/config"
	"lain/internal/fuzzer"
	"lain/internal/scorer"
	"lain/internal/types"
)

func routeDisplayPath(r types.Route) string {
	if len(r.Params) == 0 {
		return r.Path
	}
	return r.Path + "?" + strings.Join(r.Params, "&")
}

// Progress reports a completed route during a scan.
type Progress struct {
	Done     int
	Total    int
	Route    types.Route
	Findings int
}

func RunScan(cfg config.Config, routes []types.Route) types.ScanResult {
	return runScan(cfg, routes, nil)
}

// RunScanWithProgress is RunScan with an optional callback invoked (from worker
// goroutines) each time a route finishes fuzzing, so callers can render live
// progress. The callback must be concurrency-safe.
func RunScanWithProgress(cfg config.Config, routes []types.Route, onProgress func(Progress)) types.ScanResult {
	return runScan(cfg, routes, onProgress)
}

func runScan(cfg config.Config, routes []types.Route, onProgress func(Progress)) types.ScanResult {
	startedAt := time.Now()

	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}

	httpClient := &http.Client{Timeout: cfg.Timeout}

	jobs := make(chan types.Route, len(routes))
	for _, r := range routes {
		jobs <- r
	}
	close(jobs)

	results := make(chan types.Finding)

	var wg sync.WaitGroup
	var done atomic.Int64
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for route := range jobs {
				log.Printf("[worker %d] fuzzing %s %s", id, route.Method, routeDisplayPath(route))
				findings := fuzzer.FuzzRoute(cfg.TargetURL, route, httpClient)
				for _, f := range findings {
					results <- f
				}
				if onProgress != nil {
					onProgress(Progress{
						Done:     int(done.Add(1)),
						Total:    len(routes),
						Route:    route,
						Findings: len(findings),
					})
				}
			}
		}(i + 1)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []types.Finding
	for f := range results {
		findings = append(findings, f)
	}

	for i := range findings {
		findings[i].ID = scorer.GenerateFindingID(findings[i])
	}
	findings = scorer.Deduplicate(findings)

	return types.ScanResult{
		Findings:       findings,
		TargetsScanned: len(routes),
		StartedAt:      startedAt,
		FinishedAt:     time.Now(),
	}
}
