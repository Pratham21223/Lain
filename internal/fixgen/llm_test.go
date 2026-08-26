package fixgen

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"lain/internal/types"
)

// TestExplainMockAPI verifies the full request/parse flow against a fake
// OpenAI-compatible endpoint (request body shape, auth header, fence-stripping,
// JSON parsing) without any real network access.
func TestExplainMockAPI(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		// Fake model response with an accidental fence the client must strip.
		w.Header().Set("content-type", "application/json")
		text := "```json\n{\"root_cause\":\"bad SQL concat\",\"fix_instructions\":\"use params\"}\n```"
		w.Write([]byte(`{"choices":[{"message":{"content":` + strconv.Quote(text) + `}}]}`))
	}))
	defer server.Close()

	client := &LLMClient{
		APIKey:     "test-key",
		Model:      "test-model",
		Endpoint:   server.URL,
		HTTPClient: server.Client(),
	}
	finding := types.Finding{
		VulnType: "sqli",
		Route:    types.Route{Method: "GET", Path: "/api/users"},
		Param:    "id",
		Payload:  "' OR '1'='1",
		Evidence: "syntax error",
	}

	rootCause, fix, err := client.Explain(finding)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if rootCause != "bad SQL concat" || fix != "use params" {
		t.Errorf("parsed root_cause=%q fix_instructions=%q", rootCause, fix)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("authorization header = %q, want Bearer test-key", gotAuth)
	}
	if gotBody["model"] != "test-model" {
		t.Errorf("request model = %v, want test-model", gotBody["model"])
	}
	if gotBody["max_tokens"] != float64(400) {
		t.Errorf("request max_tokens = %v, want 400", gotBody["max_tokens"])
	}
}

// TestExplainNoAuthHeaderWhenKeyless confirms keyless backends like local
// Ollama don't get an Authorization header.
func TestExplainNoAuthHeaderWhenKeyless(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"root_cause\":\"r\",\"fix_instructions\":\"f\"}"}}]}`))
	}))
	defer server.Close()

	client := &LLMClient{Endpoint: server.URL, HTTPClient: server.Client()}
	if _, _, err := client.Explain(types.Finding{}); err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("keyless client should send no Authorization header, got %q", gotAuth)
	}
}

func TestExplainReturnsErrorOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"bad key"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &LLMClient{Endpoint: server.URL, HTTPClient: server.Client()}
	if _, _, err := client.Explain(types.Finding{}); err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}

func TestNewLLMClientDefaultsOllama(t *testing.T) {
	t.Setenv("LAIN_LLM_ENDPOINT", "")
	t.Setenv("LAIN_LLM_PROVIDER", "")
	t.Setenv("LAIN_LLM_MODEL", "")
	t.Setenv("LAIN_LLM_API_KEY", "")
	t.Setenv("OPENCODE_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	c := NewLLMClient()
	if c.Endpoint != "http://localhost:11434/v1/chat/completions" {
		t.Errorf("endpoint = %q, want ollama default", c.Endpoint)
	}
	if c.Model != "qwen2.5:7b-instruct" {
		t.Errorf("model = %q, want ollama default", c.Model)
	}
	if c.APIKey != "" {
		t.Errorf("api key = %q, want empty for keyless ollama", c.APIKey)
	}
}

func TestNewLLMClientProviderDeepseek(t *testing.T) {
	t.Setenv("LAIN_LLM_ENDPOINT", "")
	t.Setenv("LAIN_LLM_PROVIDER", "deepseek")
	t.Setenv("LAIN_LLM_MODEL", "")
	t.Setenv("LAIN_LLM_API_KEY", "sk-deepseek-test")
	t.Setenv("OPENCODE_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	c := NewLLMClient()
	if c.Endpoint != "https://api.deepseek.com/v1/chat/completions" {
		t.Errorf("endpoint = %q, want deepseek", c.Endpoint)
	}
	if c.Model != "deepseek-v4-flash" {
		t.Errorf("model = %q, want deepseek-v4-flash", c.Model)
	}
	if c.APIKey != "sk-deepseek-test" {
		t.Errorf("api key = %q, want sk-deepseek-test", c.APIKey)
	}
}

func TestNewLLMClientProviderOpenCodeGo(t *testing.T) {
	t.Setenv("LAIN_LLM_ENDPOINT", "")
	t.Setenv("LAIN_LLM_PROVIDER", "opencode-go")
	t.Setenv("LAIN_LLM_MODEL", "deepseek-v4-flash")
	t.Setenv("LAIN_LLM_API_KEY", "")
	t.Setenv("OPENCODE_API_KEY", "sk-opencode-test")
	t.Setenv("ANTHROPIC_API_KEY", "")
	c := NewLLMClient()
	if c.Endpoint != "https://opencode.ai/zen/go/v1/chat/completions" {
		t.Errorf("endpoint = %q, want opencode-go zen/go", c.Endpoint)
	}
	if c.Model != "deepseek-v4-flash" {
		t.Errorf("model = %q, want deepseek-v4-flash", c.Model)
	}
	if c.APIKey != "sk-opencode-test" {
		t.Errorf("api key = %q, want OPENCODE_API_KEY value", c.APIKey)
	}
}

func TestNewLLMClientOpenCodeKeyInfersProvider(t *testing.T) {
	t.Setenv("LAIN_LLM_ENDPOINT", "")
	t.Setenv("LAIN_LLM_PROVIDER", "")
	t.Setenv("LAIN_LLM_MODEL", "")
	t.Setenv("LAIN_LLM_API_KEY", "")
	t.Setenv("OPENCODE_API_KEY", "sk-opencode")
	t.Setenv("ANTHROPIC_API_KEY", "")
	c := NewLLMClient()
	if c.Endpoint != "https://opencode.ai/zen/go/v1/chat/completions" {
		t.Errorf("endpoint = %q, want opencode-go inferred from OPENCODE_API_KEY", c.Endpoint)
	}
	if c.Model != "deepseek-v4-flash" {
		t.Errorf("model = %q, want opencode-go default", c.Model)
	}
}

func TestNewLLMClientExplicitEndpointWins(t *testing.T) {
	t.Setenv("LAIN_LLM_ENDPOINT", "https://example.com/v1/chat/completions")
	t.Setenv("LAIN_LLM_PROVIDER", "deepseek")
	t.Setenv("LAIN_LLM_MODEL", "my-model")
	t.Setenv("LAIN_LLM_API_KEY", "")
	t.Setenv("OPENCODE_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	c := NewLLMClient()
	if c.Endpoint != "https://example.com/v1/chat/completions" {
		t.Errorf("endpoint = %q, want explicit endpoint", c.Endpoint)
	}
	if c.Model != "my-model" {
		t.Errorf("model = %q, want explicit model", c.Model)
	}
}

func TestNewLLMClientKeyPriority(t *testing.T) {
	t.Setenv("LAIN_LLM_ENDPOINT", "https://example.com/v1/chat/completions")
	t.Setenv("LAIN_LLM_PROVIDER", "")
	t.Setenv("LAIN_LLM_MODEL", "")
	t.Setenv("LAIN_LLM_API_KEY", "sk-lain")
	t.Setenv("OPENCODE_API_KEY", "sk-opencode")
	t.Setenv("ANTHROPIC_API_KEY", "sk-anthropic")
	c := NewLLMClient()
	if c.APIKey != "sk-lain" {
		t.Errorf("api key = %q, want LAIN_LLM_API_KEY to win", c.APIKey)
	}
}
