package bruteforce

import (
	"log"
	"net/http"
	"strings"
	"sync"

	"lain/internal/types"
)

var DefaultWordlist = []string{
	"admin", "api", "backup", "config", "debug", "test", ".env",
	"login", "dashboard", "files", "search", "internal", "staging",
	"assets", "uploads", "downloads", "static", "public", "images",
	"robots.txt", "sitemap.xml", "health", "status", "version", "swagger",
	"graphql", "metrics", "docs", "old", "tmp", "data", "users",
}

func BruteForce(baseURL string, wordlist []string, httpClient *http.Client, concurrency int) []types.Route {
	if concurrency < 1 {
		concurrency = 1
	}
	baseURL = strings.TrimRight(baseURL, "/")

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	routes := make([]types.Route, 0)

	for _, word := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()

			path := "/" + word
			resp, err := httpClient.Get(baseURL + path)
			if err != nil {
				log.Printf("bruteforce: error requesting %s%s: %v", baseURL, path, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				log.Printf("bruteforce: discovered %d %s%s", resp.StatusCode, baseURL, path)
				mu.Lock()
				routes = append(routes, types.Route{Method: "GET", Path: path})
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()
	return routes
}
