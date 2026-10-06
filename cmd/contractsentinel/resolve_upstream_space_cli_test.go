package main

import (
	"strings"
	"testing"
)

// These tests drive the direct-space-in-upstream-base-path rule at the
// command boundary: the way a user observes it is a config file with a
// "base path" upstream plus a request on stdin and the exit status /
// stdout / stderr of the whole resolve command, with no network I/O.

// TestResolveCLIUpstreamBasePathSpaceRejectsConfig covers:
//   - a direct U+0020 in the base path (segment interior, beside a slash,
//     at the end) makes the whole config invalid_config, even when the
//     request only hits the other, valid route;
//   - failure exits non-zero, leaves stdout completely empty and puts one
//     JSON error on stderr whose reason names the 1-based route position,
//     the route id and the upstream field and calls it an unencoded space —
//     an address-content error, not broken config JSON;
//   - JSON's   escape decodes to the same direct space and is rejected;
//   - config validation precedes request parsing, so the space-bearing
//     config plus an invalid request still yields invalid_config;
//   - a percent-encoded space (%20) stays legal path content and joins
//     byte for byte, including the headline example.
func TestResolveCLIUpstreamBasePathSpaceRejectsConfig(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
	}{
		{"space inside a segment", "http://admin.internal/base path"},
		{"space before a slash", "http://admin.internal/base /x"},
		{"space after a slash", "http://admin.internal/base/ x"},
		{"space at the end of the address", "http://admin.internal/base "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			// The request hits the valid first route only.
			res := runResolveCLI(t, config, cliSuccessRequest)

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
			if fail.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "upstream", "unencoded space"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Errorf("a direct space is an address-content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}

	// A JSON \u0020 escape in the upstream string decodes to a direct U+0020
	// and is rejected by the same content rule. This is a Go raw string, so
	// the backslash-u-0-0-2-0 sequence survives as six literal JSON bytes
	// (the escape a config file would hold), never as a literal space byte.
	u0020Config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/base\u0020path"}
	  ]
	}`
	res := runResolveCLI(t, u0020Config, cliSuccessRequest)
	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want empty", res.stdout)
	}
	var escFail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &escFail)
	if escFail.Code != "invalid_config" || !strings.Contains(escFail.Reason, "unencoded space") {
		t.Fatalf("got %+v, want invalid_config with the unencoded-space reason", escFail)
	}

	// Config validation precedes request parsing: the space-bearing config
	// plus broken request JSON still yields invalid_config, not
	// invalid_request.
	badConfig := `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/x","upstream":"http://x.internal/base path"}]}`
	priority := runResolveCLI(t, badConfig, `{not json`)
	if priority.exitCode == 0 || len(priority.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", priority.exitCode, priority.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, priority.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config to take priority", fail.Code)
	}
}

// TestResolveCLIUpstreamBasePathEncodedSpaceStaysLegal drives the encoded
// side of the rule at the command boundary: only a DIRECT space is banned.
// "%20" is legal path content, must not be decoded first and then rejected,
// and reaches upstreamURL byte for byte together with the untouched query
// string; the matched routeId is unchanged.
func TestResolveCLIUpstreamBasePathEncodedSpaceStaysLegal(t *testing.T) {
	// Headline: prefix /api, upstream .../base%20path, GET
	// /api/items?x=%2f&x= -> .../base%20path/items?x=%2f&x=.
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/base%20path"}
	  ]
	}`
	success := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"GET","target":"/api/items?x=%2f&x="}`))
	if success.RouteID != "api" {
		t.Errorf("routeId = %q, want api", success.RouteID)
	}
	if want := "http://api.internal/base%20path/items?x=%2f&x="; success.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, want)
	}

	// Hex casing and a space-encoded segment right at the junction survive
	// the same way.
	cases := []struct {
		name     string
		upstream string
		target   string
		routeID  string
		want     string
	}{
		{
			name:     "lowercase hex keeps its spelling",
			upstream: "http://h.internal/base%20tail",
			target:   "/x",
			routeID:  "r",
			want:     "http://h.internal/base%20tail/x",
		},
		{
			name:     "encoded space before the junction slash",
			upstream: "http://h.internal/base%20",
			target:   "/x",
			routeID:  "r",
			want:     "http://h.internal/base%20/x",
		},
		{
			name:     "encoded space in the joined remainder is untouched too",
			upstream: "http://h.internal/base",
			target:   "/x%20y",
			routeID:  "r",
			want:     "http://h.internal/base/x%20y",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"` + tc.upstream + `"}]}`
			request := `{"method":"GET","target":"` + tc.target + `"}`
			ok := assertResolveSuccess(t, runResolveCLI(t, cfg, request))
			if ok.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", ok.RouteID, tc.routeID)
			}
			if ok.UpstreamURL != tc.want {
				t.Errorf("upstreamURL = %q, want %q", ok.UpstreamURL, tc.want)
			}
		})
	}
}
