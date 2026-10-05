package main

import (
	"reflect"
	"strings"
	"testing"
)

// These tests pin the raw-encoded prefix matching contract at the command
// boundary, the way a user observes it: a config file argument, one JSON
// request on stdin, and the exit status / stdout / stderr of the whole
// command. A configured pathPrefix matches the request path byte for byte,
// exactly as written — "/files/a%2Fb", "/files/a%2fb" and "/files/a/b" are
// three different routes even though they decode to the same path, and the
// request's own spelling decides which one serves it. Everything runs
// offline: the upstreams are never contacted.

// rawPrefixCLIConfig holds the three decode-equal spellings plus a root
// fallback, all in one legal configuration.
const rawPrefixCLIConfig = `{
  "routes": [
    {"id": "enc-upper", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://upper.internal/u"},
    {"id": "enc-lower", "methods": ["GET"], "pathPrefix": "/files/a%2fb", "upstream": "http://lower.internal/l"},
    {"id": "plain",     "methods": ["GET"], "pathPrefix": "/files/a/b",   "upstream": "http://plain.internal/p"},
    {"id": "root",      "methods": ["*"],   "pathPrefix": "/",            "upstream": "http://fallback.internal/base"}
  ]
}`

// TestResolveCLIRawEncodedPrefixSelection drives the three coexisting
// spellings end to end: each request is served only by the route its raw
// path spelling hits, the stripped prefix is that raw spelling, and the
// remainder and query reach upstreamURL byte for byte.
func TestResolveCLIRawEncodedPrefixSelection(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "uppercase escape selects the uppercase route",
			target:   "/files/a%2Fb/x?keep=1&keep=&flag",
			routeID:  "enc-upper",
			upstream: "http://upper.internal/u/x?keep=1&keep=&flag",
		},
		{
			name:     "lowercase escape selects the lowercase route",
			target:   "/files/a%2fb/x",
			routeID:  "enc-lower",
			upstream: "http://lower.internal/l/x",
		},
		{
			name:     "literal slashes select the plain route",
			target:   "/files/a/b/x",
			routeID:  "plain",
			upstream: "http://plain.internal/p/x",
		},
		{
			name:     "exact encoded prefix keeps one junction slash",
			target:   "/files/a%2Fb",
			routeID:  "enc-upper",
			upstream: "http://upper.internal/u/",
		},
		{
			name:     "remainder escapes keep their spelling and case",
			target:   "/files/a%2Fb/%41%2fZ",
			routeID:  "enc-upper",
			upstream: "http://upper.internal/u/%41%2fZ",
		},
		{
			name:     "query holding another route's prefix adds no candidate",
			target:   "/other?redirect=/files/a%2Fb/x",
			routeID:  "root",
			upstream: "http://fallback.internal/base/other?redirect=/files/a%2Fb/x",
		},
		{
			name:     "encoded slash after a prefix is not a segment boundary",
			target:   "/files/a%2Fb%2Fc/x",
			routeID:  "root",
			upstream: "http://fallback.internal/base/files/a%2Fb%2Fc/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, rawPrefixCLIConfig, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}
}

// TestResolveCLIRawPrefixNotFound drives the no-candidate outcome at the
// boundary: without a fallback route, a request whose raw spelling hits no
// configured prefix exits non-zero, leaves stdout completely empty and emits
// one JSON route_not_found error on stderr — decoding the path or unifying
// the escape case to find a candidate is not allowed.
func TestResolveCLIRawPrefixNotFound(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "enc", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://enc.internal/e"}
	  ]
	}`
	cases := []struct {
		name   string
		target string
	}{
		{"literal slashes decode to the prefix but are spelled differently", "/files/a/b/x"},
		{"only the escape case differs", "/files/a%2fb/x"},
		{"encoded slash after the prefix is not a boundary", "/files/a%2Fb%2Fc/x"},
		{"query holding the full prefix adds no candidate", "/other?next=/files/a%2Fb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runResolveCLI(t, config, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
			}
			var fail struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "route_not_found" {
				t.Fatalf("code = %q, want route_not_found", fail.Code)
			}
			if fail.Reason == "" {
				t.Fatal("reason must be non-empty")
			}
		})
	}
}

// TestResolveCLIRawPrefixConflict drives the tied-candidate outcome at the
// boundary: two routes on the identical raw prefix conflict with candidate
// ids in lexicographic order, while the routes whose prefixes merely decode
// to the same path never matched the raw request and stay out of the list.
func TestResolveCLIRawPrefixConflict(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "zeta",  "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://z.internal"},
	    {"id": "alpha", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://a.internal"},
	    {"id": "lower", "methods": ["GET"], "pathPrefix": "/files/a%2fb", "upstream": "http://l.internal"},
	    {"id": "plain", "methods": ["GET"], "pathPrefix": "/files/a/b",   "upstream": "http://p.internal"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/files/a%2Fb/x"}`)

	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
	}
	var fail struct {
		Code       string   `json:"code"`
		Reason     string   `json:"reason"`
		Candidates []string `json:"candidates"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "route_conflict" {
		t.Fatalf("code = %q, want route_conflict", fail.Code)
	}
	wantCandidates := []string{"alpha", "zeta"}
	if !reflect.DeepEqual(fail.Candidates, wantCandidates) {
		t.Errorf("candidates = %v, want %v (sorted, decoded lookalikes excluded)",
			fail.Candidates, wantCandidates)
	}
	for _, excluded := range []string{"lower", "plain"} {
		for _, got := range fail.Candidates {
			if got == excluded {
				t.Errorf("candidates = %v must not contain %q: its raw prefix never matched",
					fail.Candidates, excluded)
			}
		}
	}

	// The lowercase spelling resolves on its own through the same config:
	// only the one raw-matching route is ever its candidate.
	success := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"GET","target":"/files/a%2fb/x"}`))
	if success.RouteID != "lower" {
		t.Errorf("routeId = %q, want lower", success.RouteID)
	}
	if want := "http://l.internal/x"; success.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, want)
	}
}

// TestResolveCLIRawPrefixLongestWins drives the precedence rule with encoded
// spellings at the boundary: the longer encoded prefix beats a shorter
// prefix's concrete method even as a wildcard, and a concrete method at the
// same longest prefix beats the wildcard there.
func TestResolveCLIRawPrefixLongestWins(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "short-get", "methods": ["GET"], "pathPrefix": "/files",       "upstream": "http://short.internal/s"},
	    {"id": "long-wild", "methods": ["*"],   "pathPrefix": "/files/a%2Fb", "upstream": "http://wild.internal/w"},
	    {"id": "long-get",  "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://exact.internal/e"}
	  ]
	}`
	cases := []struct {
		name     string
		method   string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "concrete method at the longest prefix wins",
			method:   "GET",
			target:   "/files/a%2Fb/x",
			routeID:  "long-get",
			upstream: "http://exact.internal/e/x",
		},
		{
			name:     "longer wildcard beats shorter concrete route",
			method:   "POST",
			target:   "/files/a%2Fb/x",
			routeID:  "long-wild",
			upstream: "http://wild.internal/w/x",
		},
		{
			name:     "shorter route still serves paths off the encoded prefix",
			method:   "GET",
			target:   "/files/other",
			routeID:  "short-get",
			upstream: "http://short.internal/s/other",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"` + tc.method + `","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, config, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}
}

// TestResolveCLIRawPrefixLiteralVsEncodedChar pins the ordinary-character
// form of the rule at the boundary: "/item/A" and "/item/%41" decode to the
// same path but are separate routes, each serving only its own spelling.
func TestResolveCLIRawPrefixLiteralVsEncodedChar(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "literal", "methods": ["GET"], "pathPrefix": "/item/A",   "upstream": "http://literal.internal/a"},
	    {"id": "encoded", "methods": ["GET"], "pathPrefix": "/item/%41", "upstream": "http://encoded.internal/e"}
	  ]
	}`
	cases := []struct {
		target   string
		routeID  string
		upstream string
	}{
		{"/item/A/1", "literal", "http://literal.internal/a/1"},
		{"/item/%41/1", "encoded", "http://encoded.internal/e/1"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			success := assertResolveSuccess(t, runResolveCLI(t, config,
				`{"method":"GET","target":"`+tc.target+`"}`))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}
}

// guard against the reason wording regressing to something that claims a
// decode happened: route_not_found must talk about the request, not about
// decoded paths.
func TestResolveCLIRawPrefixNotFoundReasonWording(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "enc", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://enc.internal/e"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/files/a/b/x"}`)
	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "route_not_found" {
		t.Fatalf("code = %q, want route_not_found", fail.Code)
	}
	if !strings.Contains(fail.Reason, "no route matches") {
		t.Errorf("reason = %q, want the existing no-route-matches wording", fail.Reason)
	}
}
