package main

import (
	"strings"
	"testing"
	"time"
)

// These tests pin the pathPrefix direct-character rule at the command
// boundary: the resolve command reads and validates the whole configuration
// before it touches the request, so a direct ASCII space, C0 control byte
// or DEL in any route's pathPrefix fails the run as invalid_config even when
// the request would only match another, earlier legal route — and even when
// the request itself is invalid. Percent-encoded bytes stay legal and match
// on the raw spelling, including the "/a%20b" route serving "/a%20b/items".

// TestResolveCLIPrefixDirectControlCharacterRejectsConfig drives the
// failure contract: non-zero exit, completely empty stdout and one JSON
// invalid_config object on stderr naming the pathPrefix field, the route's
// 1-based position, its valid non-empty id and the first offending
// character as U+XXXX — a content error, never a JSON syntax failure. The
// request matches the first route only, and a variant whose request is
// itself invalid still reports the config error first.
func TestResolveCLIPrefixDirectControlCharacterRejectsConfig(t *testing.T) {
	// "\t" is a JSON tab escape; once decoded route 2's prefix is
	// "/admin	area". A literal space and a unicode-space escape are
	// covered in the package tests with identical reasons.
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin\tarea", "upstream": "http://admin.internal"}
	  ]
	}`
	want := []string{"route 2", `"admin"`, "pathPrefix", "U+0009"}
	forbidden := []string{"not valid JSON"}

	// The request would only hit the legal first route; the read still fails.
	assertCLIInvalidConfig(t, config, `{"method":"GET","target":"/api/items"}`, want, forbidden)

	// An invalid request (a direct newline in the target) still loses to the
	// config error because the config is validated before stdin is read.
	assertCLIInvalidConfig(t, config, `{"method":"GET","target":"/api/a\nb"}`, want, forbidden)
}

// TestResolveCLIPrefixDirectSpaceFailureExitsBeforeStdin proves the read
// fails while the request pipe is still held open: the command exits on its
// own with the invalid_config failure rather than blocking on a request or
// surfacing the problem later as invalid_request.
func TestResolveCLIPrefixDirectSpaceFailureExitsBeforeStdin(t *testing.T) {
	// Build the prefix "/a b" through its JSON unicode-space spelling so the
	// source keeps no literal control byte; it decodes to the same direct
	// space.
	config := `{
	  "routes": [
	    {"id": "hit", "methods": ["*"], "pathPrefix": "/", "upstream": "http://hit.internal"},
	    {"id": "bad", "methods": ["GET"], "pathPrefix": "/a\u00` + `20b", "upstream": "http://bad.internal"}
	  ]
	}`
	p := startResolveCLI(t, config)

	res := p.awaitExit(t, 10*time.Second, "pathPrefix with a direct space")
	assertCLIInvalidConfigFailure(t, res,
		[]string{"route 2", `"bad"`, "pathPrefix", "U+0020"},
		[]string{"not valid JSON", "invalid_request"})
}

// TestResolveCLIPrefixPercentEncodedSpaceResolves drives the success
// contract at the boundary: a "%20" in the pathPrefix is ordinary raw path
// content, never decoded before validation or matching, so the route serves
// its raw-spelled requests (including "/a%20b/items"), keeps segment
// boundaries and joins the remainder the usual way. The "%09" and "%00"
// spellings resolve too.
func TestResolveCLIPrefixPercentEncodedSpaceResolves(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "enc", "methods": ["GET"], "pathPrefix": "/a%20b", "upstream": "http://enc.internal/e"},
	    {"id": "ctl", "methods": ["GET"], "pathPrefix": "/a%09b", "upstream": "http://ctl.internal/c"},
	    {"id": "root", "methods": ["*"], "pathPrefix": "/", "upstream": "http://fallback.internal/base"}
	]}`
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{"%20 prefix serves /a%20b/items", "/a%20b/items", "enc", "http://enc.internal/e/items"},
		{"exact %20 prefix keeps one junction slash", "/a%20b", "enc", "http://enc.internal/e/"},
		{"%09 prefix serves its raw spelling", "/a%09b/items", "ctl", "http://ctl.internal/c/items"},
		{"raw query is preserved through the encoded route", "/a%20b?x=%00%7F&y=2", "enc",
			"http://enc.internal/e/?x=%00%7F&y=2"},
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

	// A request that decoded the space carries it directly and is rejected
	// before route selection, so it never reaches the "%20" route.
	res := runResolveCLI(t, config, `{"method":"GET","target":"/a b/items"}`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_request" || !strings.Contains(fail.Reason, "U+0020") {
		t.Fatalf("got %+v, want invalid_request naming U+0020", fail)
	}
}
