package contractsentinel

import (
	"strings"
	"testing"
)

// TestInvalidConfigUpstreamBasePathSpace pins the direct-space rule for the
// upstream base path: a literal ASCII space (U+0020) anywhere in the base
// path — inside a path segment, beside a slash or at the end — rejects the
// whole configuration as invalid_config, whether the space was written
// directly or spelled " " in the JSON string (both decode to the same
// byte). The reason is a content error naming the route's 1-based position,
// its id and the upstream field, never a JSON syntax failure, and no config
// is handed back.
func TestInvalidConfigUpstreamBasePathSpace(t *testing.T) {
	badUpstreams := []struct {
		name     string
		upstream string
	}{
		{"space inside a path segment", "http://api.internal/base path"},
		{"space beside a slash", "http://api.internal/base /next"},
		{"space before a slash", "http://api.internal/base /"},
		{"trailing space", "http://api.internal/basepath "},
		{"several spaces", "http://api.internal/a b/c d"},
		{"space is the whole base path", "http://api.internal/ "},
		{"https with port and userinfo", "https://user:pw@api.internal:8443/v1 /x"},
		{"JSON-escaped space", `http://api.internal/base\u0020path`},
	}
	for _, tc := range badUpstreams {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
			  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"` + tc.upstream + `"}
			]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("expected invalid_config for upstream %q", tc.upstream)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "upstream", "base path", "space"} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("a space in the base path is a content error, not a JSON syntax failure: %q", f.Reason)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
		})
	}

	// The offending route may be one the request never hits: the read still
	// fails up front instead of letting the first, valid route resolve.
	cfg, f := ParseConfig([]byte(`{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"http://api.internal/base path"}
	]}`))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("unhit route with a spaced upstream: got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}
}

// TestResolveUpstreamBasePathEncodedSpace pins the other half of the rule:
// the check is only against a direct ASCII space, never against legal path
// content. A percent-encoded "%20" in the base path is data, not a direct
// character, and is carried byte for byte into upstreamURL; the join, the
// matched routeId and the raw query string are unchanged. Other Unicode
// whitespace (e.g. U+00A0) is not widened into the rule either.
func TestResolveUpstreamBasePathEncodedSpace(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/base%20path"}
	]}`)
	req, f := ParseRequest([]byte(`{"method":"GET","target":"/api/items?x=%2f&x="}`))
	if f != nil {
		t.Fatalf("ParseRequest: %+v", f)
	}
	res, rf := Resolve(cfg, req)
	if rf != nil {
		t.Fatalf("Resolve: %+v", rf)
	}
	if res.RouteID != "api" {
		t.Errorf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/base%20path/items?x=%2f&x="; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// A non-ASCII whitespace byte (U+00A0, UTF-8 0xC2 0xA0) is not an ASCII
	// space: the base path keeps it verbatim and the config stays valid.
	cfgNBSP := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/base path"}
	]}`)
	resNBSP, rf := Resolve(cfgNBSP, &Request{Method: "GET", Target: "/api/items"})
	if rf != nil {
		t.Fatalf("Resolve with U+00A0 base path: %+v", rf)
	}
	if want := "http://api.internal/base path/items"; resNBSP.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", resNBSP.UpstreamURL, want)
	}
}
