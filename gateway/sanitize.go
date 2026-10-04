package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

// SanitizeHeaders removes sensitive headers per RFC 6.3.
func SanitizeHeaders(headers map[string]string, stripList []string) map[string]string {
	out := make(map[string]string, len(headers))
	block := make(map[string]bool)
	for _, h := range stripList {
		block[strings.ToLower(h)] = true
	}
	for k, v := range headers {
		lk := strings.ToLower(k)
		if block[lk] || lk == "set-cookie" || lk == "authorization" || lk == "cookie" || lk == "proxy-authorization" {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = RedactPII(v)
	}
	return out
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe = regexp.MustCompile(`\+?\d[\d\s().-]{8,}\d`)
	ssnRe   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	cardRe  = regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)
	tokenRe = regexp.MustCompile(`(?i)\b(bearer|token|jwt|sk-)[A-Za-z0-9._-]{10,}\b`)
	jwtRe   = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`)
)

// RedactPII replaces identifiable values with typed placeholders.
func RedactPII(s string) string {
	s = jwtRe.ReplaceAllString(s, "[REDACTED_JWT]")
	s = tokenRe.ReplaceAllString(s, "[REDACTED_TOKEN]")
	s = emailRe.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = ssnRe.ReplaceAllString(s, "[REDACTED_SSN]")
	s = phoneRe.ReplaceAllString(s, "[REDACTED_PHONE]")
	s = cardRe.ReplaceAllString(s, "[REDACTED_CARD]")
	return s
}

// SanitizeBody walks a JSON body and redacts PII-looking string values.
func SanitizeBody(body string, maxLen int) string {
	s := RedactPII(body)
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		redacted := walkRedact(v)
		if b, err := json.Marshal(redacted); err == nil {
			s = string(b)
		}
	}
	if len(s) > maxLen {
		s = s[:maxLen] + "...[TRUNCATED]"
	}
	return s
}

var sensitiveKeys = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"access_token": true, "refresh_token": true, "api_key": true,
	"apikey": true, "authorization": true, "credit_card": true,
	"ssn": true, "cvv": true, "pin": true,
}

func walkRedact(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if sensitiveKeys[strings.ToLower(k)] {
				t[k] = "[REDACTED]"
				continue
			}
			t[k] = walkRedact(val)
		}
		return t
	case []interface{}:
		for i := range t {
			t[i] = walkRedact(t[i])
		}
		return t
	case string:
		return RedactPII(t)
	default:
		return v
	}
}
