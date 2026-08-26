package fuzzer

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"lain/internal/scorer"
	"lain/internal/types"
)

const (
	TypeSQLi          = scorer.TypeSQLi
	TypeXSS           = scorer.TypeXSS
	TypePathTraversal = scorer.TypePathTraversal
	TypeUnauthRoute   = scorer.TypeUnauthRoute
)

type Payload struct {
	Value      string
	VulnType   string
	DetectFunc func(statusCode int, body string) (bool, string)
}

func titleFor(vulnType string) string {
	switch vulnType {
	case TypeSQLi:
		return "SQL Injection"
	case TypeXSS:
		return "Reflected XSS"
	case TypePathTraversal:
		return "Path Traversal"
	case TypeUnauthRoute:
		return "Unauthenticated sensitive route"
	default:
		return "Vulnerability"
	}
}

var sqlErrorSignatures = []string{
	"syntax error",
	"sqlite",
	"sqlstate",
	"database error",
	"result columns",
	"db error",
	`near "`,
}

func detectSQLError(baselineStatus int) func(int, string) (bool, string) {
	return func(status int, body string) (bool, string) {
		if status == http.StatusInternalServerError && baselineStatus != http.StatusInternalServerError {
			return true, fmt.Sprintf("HTTP %d response", status)
		}
		lower := strings.ToLower(body)
		for _, sig := range sqlErrorSignatures {
			if strings.Contains(lower, sig) {
				return true, fmt.Sprintf("response body contains %q", sig)
			}
		}
		return false, ""
	}
}

func detectBlindSQLi(baselineStatus int, baselineBody string) func(int, string) (bool, string) {
	bl := len(baselineBody)
	return func(status int, body string) (bool, string) {
		if status != baselineStatus || status != http.StatusOK {
			return false, ""
		}
		cl := len(body)
		diff := cl - bl
		if diff < 0 {
			diff = -diff
		}
		if bl == 0 || diff <= 40 {
			return false, ""
		}
		ratio := float64(cl) / float64(bl)
		if ratio > 1.5 || ratio < 0.5 {
			return true, fmt.Sprintf("response body length %d vs baseline %d", cl, bl)
		}
		return false, ""
	}
}

func detectReflectedXSS(payload string) func(int, string) (bool, string) {
	return func(status int, body string) (bool, string) {
		if status != http.StatusOK {
			return false, ""
		}
		if strings.Contains(body, payload) {
			return true, fmt.Sprintf("payload %q reflected unescaped in response body", payload)
		}
		return false, ""
	}
}

var fileContentSignatures = []string{
	"root:",
	"root:x:",
	"daemon:",
	"nobody:",
	"/bin/bash",
	"/usr/sbin",
	"[boot loader]",
	"[fonts]",
	"uid=",
}

func detectPathTraversal() func(int, string) (bool, string) {
	return func(status int, body string) (bool, string) {
		if status != http.StatusOK {
			return false, ""
		}
		for _, sig := range fileContentSignatures {
			if strings.Contains(body, sig) {
				return true, fmt.Sprintf("response body contains file content signature %q", sig)
			}
		}
		return false, ""
	}
}

func DefaultPayloads(baselineStatus int, baselineBody string) []Payload {
	return []Payload{
		// SQL injection — error based
		{Value: "' OR '1'='1", VulnType: TypeSQLi, DetectFunc: detectSQLError(baselineStatus)},
		{Value: "1; DROP TABLE users--", VulnType: TypeSQLi, DetectFunc: detectSQLError(baselineStatus)},
		{Value: "' UNION SELECT NULL--", VulnType: TypeSQLi, DetectFunc: detectSQLError(baselineStatus)},
		{Value: "' OR '1'='1'--", VulnType: TypeSQLi, DetectFunc: detectSQLError(baselineStatus)},
		// SQL injection — boolean based
		{Value: "1 AND 1=1", VulnType: TypeSQLi, DetectFunc: detectBlindSQLi(baselineStatus, baselineBody)},
		{Value: "1 AND 1=2", VulnType: TypeSQLi, DetectFunc: detectBlindSQLi(baselineStatus, baselineBody)},
		// Reflected XSS
		{Value: "<script>alert(1)</script>", VulnType: TypeXSS, DetectFunc: detectReflectedXSS("<script>alert(1)</script>")},
		{Value: "\"><img src=x onerror=alert(1)>", VulnType: TypeXSS, DetectFunc: detectReflectedXSS("\"><img src=x onerror=alert(1)>")},
		{Value: "<svg/onload=alert(1)>", VulnType: TypeXSS, DetectFunc: detectReflectedXSS("<svg/onload=alert(1)>")},
		{Value: "</script><script>alert(1)</script>", VulnType: TypeXSS, DetectFunc: detectReflectedXSS("</script><script>alert(1)</script>")},
		{Value: "javascript:alert(1)", VulnType: TypeXSS, DetectFunc: detectReflectedXSS("javascript:alert(1)")},
		// Path traversal
		{Value: "../../../etc/passwd", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
		{Value: "../../../../../../etc/passwd", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
		{Value: "../../../../../../../etc/passwd", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
		{Value: "....//....//....//etc/passwd", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
		{Value: "....//....//....//....//....//....//etc/passwd", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
		{Value: "../../../../../../etc/group", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
		{Value: "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", VulnType: TypePathTraversal, DetectFunc: detectPathTraversal()},
	}
}

func get(client *http.Client, rawURL string) (int, string, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

func buildQueryURL(baseURL, path, param, value string) string {
	return baseURL + path + "?" + url.Values{param: []string{value}}.Encode()
}

var sensitiveMarkers = []string{
	"admin",
	"dashboard",
	"config",
	"internal",
	"staging",
	"debug",
	"swagger",
	"graphql",
	"metrics",
	"backup",
	"console",
	"logs",
	"settings",
}

func checkUnauthenticated(baseURL string, route types.Route, client *http.Client) *types.Finding {
	lower := strings.ToLower(route.Path)
	sensitive := false
	for _, m := range sensitiveMarkers {
		if strings.Contains(lower, m) {
			sensitive = true
			break
		}
	}
	if !sensitive {
		return nil
	}

	status, _, err := get(client, baseURL+route.Path)
	if err != nil {
		log.Printf("fuzzer: auth check request failed for %s: %v", route.Path, err)
		return nil
	}
	if status != http.StatusOK {
		return nil
	}

	return &types.Finding{
		Title:    titleFor(TypeUnauthRoute),
		Severity: scorer.Severity(TypeUnauthRoute),
		VulnType: TypeUnauthRoute,
		Route:    route,
		Evidence: fmt.Sprintf("request returned HTTP %d to sensitive route with no auth header", status),
		Location: route.Method + " " + route.Path,
	}
}

func FuzzRoute(baseURL string, route types.Route, httpClient *http.Client) []types.Finding {
	baseURL = strings.TrimRight(baseURL, "/")

	if len(route.Params) == 0 {
		if f := checkUnauthenticated(baseURL, route, httpClient); f != nil {
			return []types.Finding{*f}
		}
		return nil
	}

	var findings []types.Finding
	for _, param := range route.Params {
		baseStatus, baseBody, err := get(httpClient, buildQueryURL(baseURL, route.Path, param, "1"))
		if err != nil {
			log.Printf("fuzzer: baseline request failed for %s%s?%s: %v", baseURL, route.Path, param, err)
			continue
		}

		reported := make(map[string]bool)
		for _, p := range DefaultPayloads(baseStatus, baseBody) {
			status, body, err := get(httpClient, buildQueryURL(baseURL, route.Path, param, p.Value))
			if err != nil {
				log.Printf("fuzzer: request failed for %s?%s=%s: %v", route.Path, param, p.Value, err)
				continue
			}

			matched, evidence := p.DetectFunc(status, body)
			if !matched || reported[p.VulnType] {
				continue
			}
			reported[p.VulnType] = true

			findings = append(findings, types.Finding{
				Title:    titleFor(p.VulnType),
				Severity: scorer.Severity(p.VulnType),
				VulnType: p.VulnType,
				Route:    route,
				Param:    param,
				Payload:  p.Value,
				Evidence: evidence,
				Location: route.Method + " " + route.Path + "?" + param,
			})
		}
	}
	return findings
}
