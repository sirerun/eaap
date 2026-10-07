package main

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	// Long digit runs -> path parameter
	numericSeg = regexp.MustCompile(`^\d{2,}$`)
	// UUIDs -> path parameter
	uuidSeg = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// Hex hashes (>=16 chars) -> path parameter
	hashSeg = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	// Base64-ish opaque IDs
	opaqueID = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
)

// NormalizeURL converts e.g. /api/users/1234/profile -> /api/users/{param1}/profile
// per RFC 5.1. paramN indices are assigned in order of appearance per template.
func NormalizeURL(rawURL string) (template string, params []string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", nil
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	var out []string
	n := 0
	for _, s := range segs {
		if s == "" {
			continue
		}
		if isDynamicSeg(s) || !safeStaticSegment(s) {
			n++
			p := "param" + itoa(n)
			out = append(out, "{"+p+"}")
			params = append(params, p)
		} else {
			out = append(out, s)
		}
	}
	t := "/" + strings.Join(out, "/")
	if u.RawQuery != "" {
		t += "?<query-schema>"
	}
	return t, params
}

func safeStaticSegment(s string) bool {
	return regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`).MatchString(s) && !regexp.MustCompile(`(?i)(token|auth|secret|session|credential|key)`).MatchString(s)
}

func isDynamicSeg(s string) bool {
	return numericSeg.MatchString(s) || uuidSeg.MatchString(s) ||
		hashSeg.MatchString(s) || opaqueID.MatchString(s)
}

func normalizePath(path string) string {
	template, _ := NormalizeURL(path)
	return template
}

// RouteKey is the normalized method+template used to group traffic samples.
type TrafficSample struct {
	Method        string            `json:"method"`
	Template      string            `json:"template"`
	URLTemplate   string            `json:"url_template"`
	ParamValues   map[string]string `json:"param_values,omitempty"`
	RequestHead   map[string]string `json:"request_headers,omitempty"`
	RequestBody   string            `json:"request_body,omitempty"`
	ResponseHead  map[string]string `json:"response_headers,omitempty"`
	ResponseBody  string            `json:"response_body,omitempty"`
	StatusCode    int               `json:"status_code"`
	Host          string            `json:"host"`
	IsStaticAsset bool              `json:"is_static_asset"`
}

// GroupSamples keys samples by normalized route, keeping a bounded sample set.
func GroupSamples(samples []TrafficSample, maxPerRoute int) map[string][]TrafficSample {
	grouped := make(map[string][]TrafficSample)
	for _, s := range samples {
		if s.IsStaticAsset {
			continue
		}
		key := s.Method + " " + s.Template
		if len(grouped[key]) < maxPerRoute {
			grouped[key] = append(grouped[key], s)
		}
	}
	// Deterministic ordering
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string][]TrafficSample, len(keys))
	for _, k := range keys {
		out[k] = grouped[k]
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
