package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNormalization(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "parameterizes numeric IDs", in: "/api/users/12345/profile", want: "/api/users/{param1}/profile"},
		{name: "preserves static paths", in: "/api/workshop", want: "/api/workshop"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePath(tc.in); got != tc.want {
				t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeRedactsSecrets(t *testing.T) {
	in := map[string]string{
		"Authorization": "Bearer sk-abc123",
		"Cookie":        "session=xyz",
		"X-Custom":      "keep",
	}
	out := SanitizeHeaders(in, nil)
	if out["Authorization"] != "[REDACTED]" || out["Cookie"] != "[REDACTED]" {
		t.Errorf("secrets not redacted: %v", out)
	}
	if out["X-Custom"] != "keep" {
		t.Errorf("benign header altered: %v", out)
	}
}

func TestInferSpecAgainstFakeLLM(t *testing.T) {
	client := newFakeLLMClient(t)
	spec, err := client.InferSpec(context.Background(), []TrafficSample{
		{Method: "GET", URLTemplate: "/orders", Template: "/orders", StatusCode: 200},
	})
	if err != nil {
		t.Fatalf("InferSpec: %v", err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Errorf("bad spec: %v", spec)
	}
}

func TestDiscoveryCreatesSanifuCandidateAfterSanitizing(t *testing.T) {
	var prompt string
	client := newFakeLLMClientWithCapture(t, &prompt)
	cfg := &Config{
		ListenAddr:      "127.0.0.1:18080",
		LLMAPIURL:       "https://llm.example.test/chat/completions",
		LLMModel:        "test-model",
		AllowedOrigins:  []string{"https://sanifu.run"},
		SanitizeHeaders: []string{"authorization", "cookie"},
		JitterMinMs:     0,
		JitterMaxMs:     0,
	}
	gateway := NewGateway(cfg)
	gateway.llm = client

	batch := DiscoveryBatch{Samples: []TrafficSample{
		{
			Method:       "GET",
			Template:     "/api/users/12345",
			Host:         "https://sanifu.run",
			RequestHead:  map[string]string{"Authorization": "Bearer private-token", "Accept": "application/json"},
			RequestBody:  `{"email":"visitor@example.com"}`,
			ResponseBody: `{"message":"public profile"}`,
			StatusCode:   200,
		},
		{
			Method:      "GET",
			Template:    "/api/private",
			Host:        "https://www.tiktok.com",
			RequestBody: `{"note":"must not be forwarded"}`,
		},
	}}
	encoded, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/discovery", strings.NewReader(string(encoded)))
	recorder := httptest.NewRecorder()
	gateway.handleDiscoveryIngest(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("discovery status = %d, want %d: %s", recorder.Code, http.StatusAccepted, recorder.Body)
	}

	key := "GET /api/users/{param1}"
	if _, ok := gateway.candidates[key]; !ok {
		t.Fatalf("discovery did not create normalized candidate %q", key)
	}
	for _, forbidden := range []string{"private-token", "visitor@example.com", "must not be forwarded", "www.tiktok.com"} {
		if strings.Contains(prompt, forbidden) {
			t.Errorf("LLM prompt contains filtered or sensitive value %q", forbidden)
		}
	}
	if !strings.Contains(prompt, "[REDACTED]") || !strings.Contains(prompt, "[REDACTED_EMAIL]") {
		t.Errorf("LLM prompt is missing expected redactions: %s", prompt)
	}

	// Discovery candidates are not executable operations.
	apiRequest := httptest.NewRequest(http.MethodGet, "/api/users/67890", nil)
	apiRecorder := httptest.NewRecorder()
	gateway.handleExternalRequest(apiRecorder, apiRequest)
	if apiRecorder.Code != http.StatusNotFound || !strings.Contains(apiRecorder.Body.String(), "no promoted operation") {
		t.Errorf("candidate became executable: status=%d body=%q", apiRecorder.Code, apiRecorder.Body.String())
	}
}

func newFakeLLMClient(t *testing.T) *LLMClient {
	t.Helper()
	return newFakeLLMClientWithCapture(t, nil)
}

func newFakeLLMClientWithCapture(t *testing.T, prompt *string) *LLMClient {
	t.Helper()
	cfg := &Config{LLMAPIURL: "https://llm.example.test/chat/completions", LLMModel: "test", LLMAPIKey: "k"}
	client := NewLLMClient(cfg)
	client.http = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != cfg.LLMAPIURL {
			t.Errorf("unexpected LLM request: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("LLM request missing configured authorization")
		}
		if prompt != nil {
			var payload struct {
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("decode LLM request: %v", err)
			} else if len(payload.Messages) != 0 {
				*prompt = payload.Messages[len(payload.Messages)-1].Content
			}
		}
		body := `{"choices":[{"message":{"content":"{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"test\",\"version\":\"1\"},\"paths\":{}}"}}]}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}
	return client
}
