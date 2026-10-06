package main

import (
	"strings"
	"testing"
)

// These tests pin the upstream port-range rule at the command boundary: the
// resolve command reads and validates the whole configuration before it
// touches stdin, so an explicitly written numeric port outside the TCP range
// 0–65535 in any route fails the run as invalid_config even when the request
// would only match another, legal route — with a non-zero exit, completely
// empty stdout and one JSON failure object on stderr whose reason names the
// upstream field, the route's 1-based position and its id. A legal in-range
// port keeps its configured spelling (leading zeros included) in
// upstreamURL, and the whole flow stays offline.

// TestResolveCLIUpstreamPortOutOfRangeRejectsConfig drives the failure
// contract for the headline shapes: a domain and a bracketed IPv6 host with a
// port one or more above 65535, and a digit string long enough to overflow an
// integer conversion. Each request matches the first, legal route only.
func TestResolveCLIUpstreamPortOutOfRangeRejectsConfig(t *testing.T) {
	const huge = "99999999999999999999999999999999999999999999999999"
	cases := []struct {
		name     string
		upstream string
		port     string
	}{
		{"domain port one above the maximum", "http://api.internal:65536/base", "65536"},
		{"domain leading zeros stay over range", "http://api.internal:00065536/base", "00065536"},
		{"bracketed ipv6 headline address", "https://[::1]:99999/v1", "99999"},
		{"bracketed ipv6 one above the maximum", "http://[2001:db8::1]:65536/base", "65536"},
		{"ipv4 huge overflowing digit string", "http://192.0.2.1:" + huge + "/v1", huge},
		{"bracketed ipv6 huge overflowing digit string", "https://[::1]:" + huge, huge},
		{"over range port after userinfo", "https://user:p%40ss@api.internal:65536/v1", "65536"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			res := runResolveCLI(t, config, cliSuccessRequest)

			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want completely empty on failure (no partial result)", res.stdout)
			}
			var fail struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "upstream", tc.port, "0-65535"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, forbidden := range []string{"not valid JSON", "invalid port"} {
				if strings.Contains(fail.Reason, forbidden) {
					t.Errorf("an out-of-range numeric port is an address-content range error, not %q: %q",
						forbidden, fail.Reason)
				}
			}
		})
	}

	// Config validation precedes request parsing: even a syntactically broken
	// request still yields the over-range-port config error.
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://h:99999"}
	  ]
	}`
	res := runResolveCLI(t, config, `{not json`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config to take priority over the bad request", fail.Code)
	}
}

// TestResolveCLIUpstreamPortInRangeResolves drives the success contract at the
// boundary: 0 and 65535 (the two ends), an ordinary port and a leading-zero
// spelling all resolve, and the configured digits reach upstreamURL byte for
// byte — leading zeros are never stripped. No port and a trailing colon stay
// legal as before.
func TestResolveCLIUpstreamPortInRangeResolves(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		target   string
		wantURL  string
	}{
		{
			name:     "maximum port on a domain",
			upstream: "http://api.internal:65535/v1",
			target:   "/api/x",
			wantURL:  "http://api.internal:65535/v1/x",
		},
		{
			name:     "port zero on a bracketed ipv6 host",
			upstream: "https://[::1]:0/v1",
			target:   "/api/x",
			wantURL:  "https://[::1]:0/v1/x",
		},
		{
			name:     "leading zero maximum keeps its original spelling",
			upstream: "http://api.internal:00065535/v1",
			target:   "/api/x?z=1",
			wantURL:  "http://api.internal:00065535/v1/x?z=1",
		},
		{
			name:     "in range port after userinfo and an ipv6 literal",
			upstream: "https://user:p%40ss@[2001:db8::1]:8443/v1",
			target:   "/api/x",
			wantURL:  "https://user:p%40ss@[2001:db8::1]:8443/v1/x",
		},
		{
			name:     "no port is unaffected",
			upstream: "http://api.internal/v1",
			target:   "/api/x",
			wantURL:  "http://api.internal/v1/x",
		},
		{
			name:     "trailing colon is an empty port and stays legal",
			upstream: "http://api.internal:/v1",
			target:   "/api/x",
			wantURL:  "http://api.internal:/v1/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` +
				tc.upstream + `"}]}`
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, config, request))
			if success.RouteID != "api" {
				t.Errorf("routeId = %q, want api", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q (port spelling must be preserved)",
					success.UpstreamURL, tc.wantURL)
			}
		})
	}
}

// TestResolveCLIUpstreamPortRangeOnlyReadsRealPort pins the boundary
// discipline at the command boundary: an over-range-looking number in userinfo
// or in the base path, and port-like hextets inside a bracketed IPv6 address,
// are not a port and must not make the config fail.
func TestResolveCLIUpstreamPortRangeOnlyReadsRealPort(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		wantURL  string
	}{
		{
			name:     "large number in userinfo is not a port",
			upstream: "http://user:65536@api.internal/v1",
			wantURL:  "http://user:65536@api.internal/v1/x",
		},
		{
			name:     "large number in the base path is not a port",
			upstream: "http://api.internal/v1/65536",
			wantURL:  "http://api.internal/v1/65536/x",
		},
		{
			name:     "numeric hextets inside brackets are not a port",
			upstream: "http://[2001:db8::1:8443]/v1",
			wantURL:  "http://[2001:db8::1:8443]/v1/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` +
				tc.upstream + `"}]}`
			success := assertResolveSuccess(t, runResolveCLI(t, config,
				`{"method":"GET","target":"/api/x"}`))
			if success.RouteID != "api" {
				t.Errorf("routeId = %q, want api", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.wantURL)
			}
		})
	}
}
