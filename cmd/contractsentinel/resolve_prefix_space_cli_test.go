package main

import (
	"testing"
	"time"
)

// These tests drive the pathPrefix direct-character rule at the real command
// boundary: a config whose pathPrefix carries, after JSON decoding, a byte a
// request target is forbidden from carrying — a direct space (U+0020), a C0
// control byte (U+0000..U+001F) or DEL (U+007F) — is rejected while the
// configuration is read, before stdin is awaited. The offending route may
// stand behind a route every request would hit; the whole file is still
// invalid_config. A percent-encoded prefix such as /a%20b stays legal and
// matches /a%20b/items on the raw encoded spelling. Everything runs
// offline; the upstreams are never contacted.

// TestResolveCLIPrefixDirectSpaceFailsBeforeStdinEOF is the timing headline:
// route 1 would answer every request, but route 2's pathPrefix carries a
// direct space, so the command exits non-zero on its own while the
// requesting program still holds stdin open and has sent nothing. stdout
// stays completely empty and stderr carries exactly one JSON error whose
// reason names pathPrefix, the 1-based route position, the route id and the
// first offending byte as U+XXXX — a content error in legal JSON, never an
// invalid_request and never a JSON parse failure.
func TestResolveCLIPrefixDirectSpaceFailsBeforeStdinEOF(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "hit", "methods": ["*"], "pathPrefix": "/", "upstream": "http://hit.internal"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin area", "upstream": "http://admin.internal"}
	  ]
	}`
	p := startResolveCLI(t, config)

	res := p.awaitExit(t, 10*time.Second, "pathPrefix with a direct space")
	assertCLIInvalidConfigFailure(t, res,
		[]string{"route 2", `"admin"`, "pathPrefix", "U+0020"},
		[]string{"not valid JSON", "invalid_request"})
}

// TestResolveCLIPrefixEscapesDecodedThenRejected proves the check runs on
// the decoded prefix: a " " JSON escape and a literal space are the same
// byte, and "\n" and "\u0000" cannot smuggle a control byte past the
// reader. Each spelling fails before stdin is read with the matching
// U+XXXX token.
func TestResolveCLIPrefixEscapesDecodedThenRejected(t *testing.T) {
	cases := []struct {
		name       string
		prefixJSON string // raw JSON string body for pathPrefix
		want       string
	}{
		{"json unicode space escape", `/a\u0020b`, "U+0020"},
		{"json newline escape", `/a\nb`, "U+000A"},
		{"json tab escape", `/a\tb`, "U+0009"},
		{"json null escape", `/a\u0000b`, "U+0000"},
		{"json del escape", `/a\u007Fb`, "U+007F"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "hit", "methods": ["*"], "pathPrefix": "/", "upstream": "http://hit.internal"},
			    {"id": "bad", "methods": ["GET"], "pathPrefix": "` + tc.prefixJSON + `", "upstream": "http://bad.internal"}
			  ]
			}`
			p := startResolveCLI(t, config)
			res := p.awaitExit(t, 10*time.Second, tc.name)
			assertCLIInvalidConfigFailure(t, res,
				[]string{"route 2", `"bad"`, "pathPrefix", tc.want},
				[]string{"not valid JSON", "invalid_request"})
		})
	}
}

// TestResolveCLIPrefixDirectCharBeatsAValidRequest proves config validation
// really precedes the request read even when bytes are available: paired
// with a well-formed request that would hit the first route, a spaced later
// route still produces invalid_config, non-zero exit and empty stdout, and
// the request never produces a resolution.
func TestResolveCLIPrefixDirectCharBeatsAValidRequest(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin area", "upstream": "http://admin.internal"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)

	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
	}
	assertCLIInvalidConfigFailure(t, res,
		[]string{"route 2", `"admin"`, "pathPrefix", "U+0020"},
		[]string{"not valid JSON", "invalid_request"})
}

// TestResolveCLIPercentEncodedPrefixStillResolves pins the encoded half of
// the rule end to end: /a%20b is a legal prefix and matches /a%20b/items,
// keeping the raw escape in the prefix match and carrying the remainder to
// upstreamURL byte for byte — no decoding before matching, no re-encoding on
// the join. Encoded control bytes (%09, %00) behave the same way.
func TestResolveCLIPercentEncodedPrefixStillResolves(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "spaced", "methods": ["GET"], "pathPrefix": "/a%20b", "upstream": "http://spaced.internal/s"},
	    {"id": "ctrl", "methods": ["GET"], "pathPrefix": "/t%09x%00", "upstream": "http://ctrl.internal/c"}
	  ]
	}`
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "encoded space prefix matches the encoded request",
			target:   "/a%20b/items",
			routeID:  "spaced",
			upstream: "http://spaced.internal/s/items",
		},
		{
			name:     "exact encoded prefix keeps one junction slash and a raw query",
			target:   "/a%20b?note=%20&x=",
			routeID:  "spaced",
			upstream: "http://spaced.internal/s/?note=%20&x=",
		},
		{
			name:     "encoded tab and null prefix matches raw and keeps the remainder",
			target:   "/t%09x%00/deep?a=1",
			routeID:  "ctrl",
			upstream: "http://ctrl.internal/c/deep?a=1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, config, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}

	// A request that decodes to the same path but spells it with a literal
	// space is rejected itself: the encoded prefix never serves a decoded
	// spelling, and the failure is invalid_request (the config is valid).
	litSpace := runResolveCLI(t, config, `{"method":"GET","target":"/a b/items"}`)
	if litSpace.exitCode == 0 || len(litSpace.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout",
			litSpace.exitCode, litSpace.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, litSpace.stderr, "stderr", &fail)
	if fail.Code != "invalid_request" {
		t.Fatalf("code = %q, want invalid_request for a literal-space target against a valid config", fail.Code)
	}
}
