package fixgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"lain/internal/types"
)

type LLMClient struct {
	APIKey     string
	Model      string
	Endpoint   string
	Enabled    bool
	HTTPClient *http.Client
}

// NewLLMClient builds a client for an OpenAI-compatible chat endpoint.
// Settings are read from the environment; `LAIN_LLM_PROVIDER` selects a preset
// when no explicit endpoint is given:
//
//	LAIN_LLM_PROVIDER  "ollama" (default) | "deepseek" | "opencode-go"
//	LAIN_LLM_ENDPOINT  full chat-completions URL; overrides the provider preset
//	LAIN_LLM_MODEL     model name (defaults per provider)
//	LAIN_LLM_API_KEY   sent as "Authorization: Bearer <key>" when set
//	                   (OPENCODE_API_KEY and ANTHROPIC_API_KEY are aliases)
//	LAIN_LLM_DISABLED=1 disables the LLM path entirely (fallback only)
//
// Presets:
//
//	ollama      http://localhost:11434/v1/chat/completions  (qwen2.5:7b-instruct)
//	deepseek    https://api.deepseek.com/v1/chat/completions (deepseek-v4-flash)
//	opencode-go https://opencode.ai/zen/go/v1/chat/completions (deepseek-v4-flash)
//
// If no endpoint is set, opencode-go is inferred when OPENCODE_API_KEY is
// present; otherwise the local Ollama default applies.
func NewLLMClient() *LLMClient {
	provider := strings.ToLower(os.Getenv("LAIN_LLM_PROVIDER"))
	endpoint := os.Getenv("LAIN_LLM_ENDPOINT")
	model := os.Getenv("LAIN_LLM_MODEL")

	if endpoint == "" && provider == "" && os.Getenv("OPENCODE_API_KEY") != "" {
		provider = "opencode-go"
	}

	if endpoint == "" {
		switch provider {
		case "deepseek":
			endpoint = "https://api.deepseek.com/v1/chat/completions"
			if model == "" {
				model = "deepseek-v4-flash"
			}
		case "opencode-go", "opencode":
			endpoint = "https://opencode.ai/zen/go/v1/chat/completions"
			if model == "" {
				model = "deepseek-v4-flash"
			}
		default:
			endpoint = "http://localhost:11434/v1/chat/completions"
			if model == "" {
				model = "qwen2.5:7b-instruct"
			}
		}
	}
	if model == "" {
		model = "qwen2.5:7b-instruct"
	}

	apiKey := os.Getenv("LAIN_LLM_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENCODE_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	return &LLMClient{
		APIKey:     apiKey,
		Model:      model,
		Endpoint:   endpoint,
		Enabled:    os.Getenv("LAIN_LLM_DISABLED") != "1",
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func buildPrompt(finding types.Finding) string {
	return fmt.Sprintf(
		"You are a security engineer reviewing an automated fuzzer finding in a Go web application. "+
			"Given: vuln type %s, route %s %s, parameter %q, payload %q, evidence %q — "+
			"explain the root cause in 1-2 plain-English sentences and give a specific, actionable "+
			"code-level fix instruction (not generic advice like 'sanitize input'). Name the exact "+
			"safe API to use for Go — e.g. database/sql parameterized queries with ? placeholders "+
			"for SQL injection, html/template auto-escaping for XSS, or filepath.Clean plus a "+
			"prefix check for path traversal — and wrap any code identifiers in backticks. "+
			"Respond only as JSON: "+
			`{"root_cause": "...", "fix_instructions": "..."}.`,
		finding.VulnType, finding.Route.Method, finding.Route.Path,
		finding.Param, finding.Payload, finding.Evidence)
}

type explanation struct {
	RootCause       string `json:"root_cause"`
	FixInstructions string `json:"fix_instructions"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func stripFences(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

func truncateBytes(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// Explain asks the model for a root cause and fix instruction for a finding.
// It never panics; all failures are returned as errors so the caller can fall back.
func (c *LLMClient) Explain(finding types.Finding) (rootCause string, fixInstructions string, err error) {
	body, err := json.Marshal(map[string]any{
		"model":      c.Model,
		"max_tokens": 400,
		"messages": []map[string]string{
			{"role": "user", "content": buildPrompt(finding)},
		},
	})
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest(http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("content-type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("authorization", "Bearer "+c.APIKey)
	}

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("LLM endpoint returned %s: %s", resp.Status, truncateBytes(respBody, 300))
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", err
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return "", "", fmt.Errorf("LLM endpoint returned empty content")
	}

	text := stripFences(parsed.Choices[0].Message.Content)
	var expl explanation
	if err := json.Unmarshal([]byte(text), &expl); err != nil {
		return "", "", fmt.Errorf("parsing model JSON response: %w; raw: %s", err, text)
	}
	return expl.RootCause, expl.FixInstructions, nil
}
