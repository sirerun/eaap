package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type LLMClient struct {
	apiURL string
	apiKey string
	model  string
	http   *http.Client
}

func NewLLMClient(cfg *Config) *LLMClient {
	apiKey := cfg.LLMAPIKey
	if apiKey == "" && cfg.LLMAPIKeyEnv != "" {
		apiKey = os.Getenv(cfg.LLMAPIKeyEnv)
	}
	return &LLMClient{
		apiURL: cfg.LLMAPIURL,
		apiKey: apiKey,
		model:  cfg.LLMModel,
		http:   &http.Client{Timeout: 120 * time.Second},
	}
}

func BuildPrompt(samples []TrafficSample) string {
	var prompt strings.Builder
	prompt.WriteString("Infer an OpenAPI 3.0.3 JSON specification from the HTTP samples below. Output only valid JSON with openapi, info, and paths fields.\n")
	for i, sample := range samples {
		fmt.Fprintf(&prompt, "\nSample %d\n", i+1)
		fmt.Fprintf(&prompt, "Normalized URL: %s\n", sample.Template)
		fmt.Fprintf(&prompt, "HTTP Method: %s\n", strings.ToUpper(sample.Method))
		fmt.Fprintf(&prompt, "Request Headers: %s\n", mustJSON(SanitizeHeaders(sample.RequestHead, []string{"authorization", "cookie", "proxy-authorization", "x-api-key"})))
		fmt.Fprintf(&prompt, "Request Body: %s\n", sample.RequestBody)
		fmt.Fprintf(&prompt, "Response Status: %d\n", sample.StatusCode)
		fmt.Fprintf(&prompt, "Response Body: %s\n", sample.ResponseBody)
	}
	return prompt.String()
}

func mustJSON(value interface{}) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func (c *LLMClient) InferSpec(ctx context.Context, samples []TrafficSample) (map[string]interface{}, error) {
	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": "Output only valid JSON for an OpenAPI 3.0.3 specification."},
			{"role": "user", "content": BuildPrompt(samples)},
		},
		"response_format": map[string]string{"type": "json_object"},
		"temperature":     0.1,
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("encode LLM request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("create LLM request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("LLM request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return nil, fmt.Errorf("LLM status %d: %s", response.StatusCode, raw)
	}

	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(response.Body).Decode(&completion); err != nil {
		return nil, fmt.Errorf("decode LLM response: %w", err)
	}
	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("LLM returned no choices")
	}

	content := strings.TrimSpace(completion.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(content), &spec); err != nil {
		return nil, fmt.Errorf("LLM output is not valid JSON: %w", err)
	}
	if err := validateSpec(spec); err != nil {
		return nil, err
	}
	return spec, nil
}

func validateSpec(spec map[string]interface{}) error {
	version, ok := spec["openapi"].(string)
	if !ok || !strings.HasPrefix(version, "3.") {
		return fmt.Errorf("spec missing OpenAPI 3.x version field")
	}
	if _, ok := spec["paths"].(map[string]interface{}); !ok {
		return fmt.Errorf("spec missing paths object")
	}
	return nil
}
