package contractsentinel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	routes := []Route{
		{ID: "api-wild", Methods: []string{"*"}, PathPrefix: "/api", Upstream: "https://up.example.com/base"},
		{ID: "api-orders", Methods: []string{"GET"}, PathPrefix: "/api/orders", Upstream: "https://up.example.com/orders-svc"},
		{ID: "root", Methods: []string{"GET", "POST"}, PathPrefix: "/", Upstream: "http://root.example.com"},
		{ID: "enc", Methods: []string{"GET"}, PathPrefix: "/files", Upstream: "https://up.example.com/dl"},
	}

	tests := []struct {
		name    string
		method  string
		target  string
		wantID  string
		wantURL string
	}{
		{
			name:   "basic hit strips prefix and joins base",
			method: "GET", target: "/api/orders/42",
			wantID: "api-orders", wantURL: "https://up.example.com/orders-svc/42",
		},
		{
			name:   "prefix matches exactly keeps junction slash",
			method: "GET", target: "/api/orders",
			wantID: "api-orders", wantURL: "https://up.example.com/orders-svc/",
		},
		{
			name:   "longest prefix wins",
			method: "GET", target: "/api/orders/list",
			wantID: "api-orders", wantURL: "https://up.example.com/orders-svc/list",
		},
		{
			name:   "shorter prefix route still matches sibling path",
			method: "POST", target: "/api/orders",
			wantID: "api-wild", wantURL: "https://up.example.com/base/orders",
		},
		{
			name:   "segment boundary: /api does not match /apiv2",
			method: "GET", target: "/apiv2",
			wantID: "root", wantURL: "http://root.example.com/apiv2",
		},
		{
			name:   "segment boundary: /api matches /api itself",
			method: "GET", target: "/api",
			wantID: "api-wild", wantURL: "https://up.example.com/base/",
		},
		{
			name:   "%2F is not a path separator",
			method: "GET", target: "/api%2Forders",
			wantID: "root", wantURL: "http://root.example.com/api%2Forders",
		},
		{
			name:   "percent encoding outside junction preserved",
			method: "GET", target: "/files/a%20b/c%3Fd",
			wantID: "enc", wantURL: "https://up.example.com/dl/a%20b/c%3Fd",
		},
		{
			name:   "query does not affect matching and is kept verbatim",
			method: "GET", target: "/api/orders?x=1&x=2&y=&z",
			wantID: "api-orders", wantURL: "https://up.example.com/orders-svc/?x=1&x=2&y=&z",
		},
		{
			name:   "empty query string kept",
			method: "GET", target: "/api?",
			wantID: "api-wild", wantURL: "https://up.example.com/base/?",
		},
		{
			name:   "root prefix keeps all following path",
			method: "GET", target: "/anything/here",
			wantID: "root", wantURL: "http://root.example.com/anything/here",
		},
		{
			name:   "root prefix with empty remainder keeps junction slash",
			method: "GET", target: "/",
			wantID: "root", wantURL: "http://root.example.com/",
		},
		{
			name:   "wildcard method matches any method",
			method: "DELETE", target: "/api/thing",
			wantID: "api-wild", wantURL: "https://up.example.com/base/thing",
		},
		{
			name:   "method is case sensitive",
			method: "get", target: "/api/orders",
			wantID: "api-wild", wantURL: "https://up.example.com/base/orders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Resolve(routes, Request{Method: tt.method, Target: tt.target})
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if res.RouteID != tt.wantID {
				t.Errorf("RouteID = %q, want %q", res.RouteID, tt.wantID)
			}
			if res.UpstreamURL != tt.wantURL {
				t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, tt.wantURL)
			}
		})
	}
}

func TestResolveUpstreamBase(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		prefix   string
		target   string
		wantURL  string
	}{
		{
			name:     "base with trailing slash, remainder with leading slash collapses",
			upstream: "https://up.example.com/base/",
			prefix:   "/api", target: "/api/orders",
			wantURL: "https://up.example.com/base/orders",
		},
		{
			name:     "base without trailing slash, empty remainder adds one",
			upstream: "https://up.example.com/base",
			prefix:   "/api", target: "/api",
			wantURL: "https://up.example.com/base/",
		},
		{
			name:     "empty base path gets single slash",
			upstream: "https://up.example.com",
			prefix:   "/api", target: "/api/orders",
			wantURL: "https://up.example.com/orders",
		},
		{
			name:     "deep base path preserved",
			upstream: "https://up.example.com/gw/v1",
			prefix:   "/api", target: "/api/x/y",
			wantURL: "https://up.example.com/gw/v1/x/y",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := []Route{{ID: "r", Methods: []string{"GET"}, PathPrefix: tt.prefix, Upstream: tt.upstream}}
			res, err := Resolve(routes, Request{Method: "GET", Target: tt.target})
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if res.UpstreamURL != tt.wantURL {
				t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, tt.wantURL)
			}
		})
	}
}

func TestResolveSelection(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		routes := []Route{{ID: "a", Methods: []string{"GET"}, PathPrefix: "/a", Upstream: "https://up.example.com"}}
		_, err := Resolve(routes, Request{Method: "GET", Target: "/b"})
		assertResolutionError(t, err, "route_not_found", nil)
	})

	t.Run("method not found on matching prefix", func(t *testing.T) {
		routes := []Route{{ID: "a", Methods: []string{"GET"}, PathPrefix: "/a", Upstream: "https://up.example.com"}}
		_, err := Resolve(routes, Request{Method: "POST", Target: "/a"})
		assertResolutionError(t, err, "route_not_found", nil)
	})

	t.Run("equal prefix and specificity conflicts, candidates sorted", func(t *testing.T) {
		routes := []Route{
			{ID: "z", Methods: []string{"GET"}, PathPrefix: "/a", Upstream: "https://up.example.com"},
			{ID: "m", Methods: []string{"GET"}, PathPrefix: "/a", Upstream: "https://up.example.com"},
		}
		_, err := Resolve(routes, Request{Method: "GET", Target: "/a"})
		assertResolutionError(t, err, "route_conflict", []string{"m", "z"})
	})

	t.Run("wildcard routes on equal prefix also conflict", func(t *testing.T) {
		routes := []Route{
			{ID: "b", Methods: []string{"*"}, PathPrefix: "/a", Upstream: "https://up.example.com"},
			{ID: "a", Methods: []string{"*"}, PathPrefix: "/a", Upstream: "https://up.example.com"},
		}
		_, err := Resolve(routes, Request{Method: "GET", Target: "/a"})
		assertResolutionError(t, err, "route_conflict", []string{"a", "b"})
	})

	t.Run("concrete method beats wildcard on equal prefix", func(t *testing.T) {
		routes := []Route{
			{ID: "wild", Methods: []string{"*"}, PathPrefix: "/a", Upstream: "https://wild.example.com"},
			{ID: "conc", Methods: []string{"GET"}, PathPrefix: "/a", Upstream: "https://conc.example.com"},
		}
		res, err := Resolve(routes, Request{Method: "GET", Target: "/a/x"})
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if res.RouteID != "conc" {
			t.Errorf("RouteID = %q, want conc", res.RouteID)
		}
	})

	t.Run("longer prefix wins even when wildcard", func(t *testing.T) {
		routes := []Route{
			{ID: "short", Methods: []string{"GET"}, PathPrefix: "/a", Upstream: "https://short.example.com"},
			{ID: "long", Methods: []string{"*"}, PathPrefix: "/a/b", Upstream: "https://long.example.com"},
		}
		res, err := Resolve(routes, Request{Method: "POST", Target: "/a/b/c"})
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if res.RouteID != "long" {
			t.Errorf("RouteID = %q, want long", res.RouteID)
		}
	})

	t.Run("empty routes never match", func(t *testing.T) {
		_, err := Resolve(nil, Request{Method: "GET", Target: "/a"})
		assertResolutionError(t, err, "route_not_found", nil)
	})
}

func assertResolutionError(t *testing.T, err error, wantCode string, wantCandidates []string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", wantCode)
	}
	re, ok := err.(*ResolutionError)
	if !ok {
		t.Fatalf("error type = %T, want *ResolutionError", err)
	}
	if re.Code != wantCode {
		t.Errorf("Code = %q, want %q", re.Code, wantCode)
	}
	if wantCandidates != nil {
		if strings.Join(re.Candidates, ",") != strings.Join(wantCandidates, ",") {
			t.Errorf("Candidates = %v, want %v", re.Candidates, wantCandidates)
		}
	}
}

func TestLoadRoutes(t *testing.T) {
	validConfig := `{
		"routes": [
			{"id":"a","methods":["GET","*"],"pathPrefix":"/a","upstream":"https://up.example.com/base"},
			{"id":"b","methods":["POST"],"pathPrefix":"/b","upstream":"http://up.example.com:8080"}
		]
	}`

	t.Run("valid config", func(t *testing.T) {
		path := writeConfig(t, validConfig)
		routes, err := LoadRoutes(path)
		if err != nil {
			t.Fatalf("LoadRoutes() error = %v", err)
		}
		if len(routes) != 2 {
			t.Errorf("len(routes) = %d, want 2", len(routes))
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		_, err := LoadRoutes(filepath.Join(t.TempDir(), "missing.json"))
		assertConfigError(t, err)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := LoadRoutes(writeConfig(t, `{"routes": [`))
		assertConfigError(t, err)
	})

	t.Run("missing routes array", func(t *testing.T) {
		_, err := LoadRoutes(writeConfig(t, `{}`))
		assertConfigError(t, err)
	})

	t.Run("empty routes array is valid", func(t *testing.T) {
		_, err := LoadRoutes(writeConfig(t, `{"routes":[]}`))
		if err != nil {
			t.Fatalf("LoadRoutes() error = %v", err)
		}
	})

	invalidConfigs := []struct {
		name   string
		config string
	}{
		{"empty id", `{"routes":[{"id":"","methods":["GET"],"pathPrefix":"/a","upstream":"https://up.example.com"}]}`},
		{"duplicate id", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"https://up.example.com"},{"id":"a","methods":["GET"],"pathPrefix":"/b","upstream":"https://up.example.com"}]}`},
		{"empty methods", `{"routes":[{"id":"a","methods":[],"pathPrefix":"/a","upstream":"https://up.example.com"}]}`},
		{"bad method", `{"routes":[{"id":"a","methods":["GE T"],"pathPrefix":"/a","upstream":"https://up.example.com"}]}`},
		{"prefix without slash", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"a","upstream":"https://up.example.com"}]}`},
		{"prefix trailing slash", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a/","upstream":"https://up.example.com"}]}`},
		{"prefix with query", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a?x=1","upstream":"https://up.example.com"}]}`},
		{"prefix with fragment", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a#f","upstream":"https://up.example.com"}]}`},
		{"upstream without host", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"https:///path"}]}`},
		{"upstream ftp", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"ftp://up.example.com"}]}`},
		{"upstream with query", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"https://up.example.com/path?x=1"}]}`},
		{"upstream with empty query", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"https://up.example.com/path?"}]}`},
		{"upstream with fragment", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"https://up.example.com/path#f"}]}`},
		{"upstream with empty fragment", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"https://up.example.com/path#"}]}`},
		{"upstream not a URL", `{"routes":[{"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"://nope"}]}`},
	}
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadRoutes(writeConfig(t, tt.config))
			assertConfigError(t, err)
		})
	}
}

func assertConfigError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected invalid_config error, got nil")
	}
	if _, ok := err.(*ConfigError); !ok {
		t.Fatalf("error type = %T, want *ConfigError", err)
	}
}

func TestParseRequest(t *testing.T) {
	valid := []string{
		`{"method":"GET","target":"/a"}`,
		`{"method":"get","target":"/a?x=1"}`,
		`{"method":"GET","target":"/a%2Fb?x=1&y="}`,
		`{"method":"OPTIONS","target":"/"}`,
	}
	for _, raw := range valid {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseRequest([]byte(raw)); err != nil {
				t.Fatalf("ParseRequest() error = %v", err)
			}
		})
	}

	invalid := []struct {
		name string
		raw  string
	}{
		{"invalid JSON", `{"method":`},
		{"missing method", `{"target":"/a"}`},
		{"empty method", `{"method":"","target":"/a"}`},
		{"whitespace method", `{"method":"GE T","target":"/a"}`},
		{"asterisk method", `{"method":"*","target":"/a"}`},
		{"target without slash", `{"method":"GET","target":"a"}`},
		{"target with fragment", `{"method":"GET","target":"/a#f"}`},
		{"target with bad percent escape", `{"method":"GET","target":"/a%2"}`},
		{"target with non-hex percent", `{"method":"GET","target":"/a%ZZ"}`},
		{"query with bad percent escape", `{"method":"GET","target":"/a?x=%2"}`},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRequest([]byte(tt.raw))
			if err == nil {
				t.Fatal("expected invalid_request error, got nil")
			}
			if _, ok := err.(*RequestError); !ok {
				t.Fatalf("error type = %T, want *RequestError", err)
			}
		})
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
