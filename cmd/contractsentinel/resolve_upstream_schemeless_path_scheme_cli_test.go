package main

import (
	"strings"
	"testing"
)

// These tests pin at the command boundary the credential-redaction fix for
// a schemeless upstream whose base path itself contains scheme text, e.g.
// //alice:pw%4@api.internal/http://mirror/v1. The leading "//" is the only
// thing that decides there is no scheme; the "http://" in the base path is
// path content and must not move the authority boundary (which would let
// the username, password and malformed credential fragment reach stderr
// verbatim). The failure contract stays: non-zero exit, completely empty
// stdout and one JSON error on stderr with code invalid_config, the reason
// locating the route by its 1-based position, id and the upstream field and
// quoting the address only as "//***@host/..." with the full base path
// (scheme text included) kept.

// TestResolveCLISchemelessSchemeTextInPathBadUserinfo drives the headline
// reader route: a truncated password escape plus literal "http://" in the
// base path is a userinfo-escape failure, and no credential byte may leak.
func TestResolveCLISchemelessSchemeTextInPathBadUserinfo(t *testing.T) {
	config := `{"routes":[
	  {"id":"reader","methods":["GET"],"pathPrefix":"/reader","upstream":"//alice:pw%4@api.internal/http://mirror/v1"}
	]}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/reader/items"}`)

	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want completely empty on failure (no half result)", res.stdout)
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", fail.Code)
	}
	for _, want := range []string{
		"route 1",
		`"reader"`,
		"upstream",
		"invalid percent escape in its userinfo",
		`"//***@api.internal/http://mirror/v1"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", "p@", `"%4"`, "//alice"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", fail.Reason, leaked)
		}
	}
	if strings.Contains(fail.Reason, "not valid JSON") {
		t.Fatalf("a schemeless upstream is a content error, not a JSON syntax failure: %q", fail.Reason)
	}
}

// TestResolveCLISchemelessSchemeTextInPathRejectsWholeConfig puts the bad
// route second, where the request never hits it: the whole config still
// fails at read time with empty stdout and the hidden credential.
func TestResolveCLISchemelessSchemeTextInPathRejectsWholeConfig(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "reader", "methods": ["GET"], "pathPrefix": "/reader", "upstream": "//alice:pw%4@api.internal/http://mirror/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)

	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want empty", res.stdout)
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", fail.Code)
	}
	for _, want := range []string{
		"route 2",
		`"reader"`,
		"upstream",
		"invalid percent escape in its userinfo",
		`"//***@api.internal/http://mirror/v1"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", `"%4"`} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", fail.Reason, leaked)
		}
	}
}

// TestResolveCLISchemelessSchemeTextInPathPathError pins the boundary when
// the credentials are legal and the malformed escape belongs to the base
// path: the path-escape diagnostic and its fragment are kept (the path's
// "https://" text, an '@' in the path included), only the credentials are
// hidden, and the failure is not relabeled a userinfo error.
func TestResolveCLISchemelessSchemeTextInPathPathError(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		creds    []string
	}{
		{
			name:     "bad path escape after scheme text",
			upstream: "//alice:p%40ss@api.internal/https://mirror/%zz",
			shown:    "//***@api.internal/https://mirror/%zz",
			creds:    []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "at sign in the path stays path content",
			upstream: "//alice:p%40ss@api.internal/https://mirror/v1@x/%zz",
			shown:    "//***@api.internal/https://mirror/v1@x/%zz",
			creds:    []string{"alice", "p%40ss", "p@ss"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"reader","methods":["GET"],"pathPrefix":"/reader","upstream":"` + tc.upstream + `"}]}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/reader/items"}`)
			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want empty", res.stdout)
			}
			var fail struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{
				"route 1",
				`"reader"`,
				"upstream",
				"not a valid URL",
				`parse "` + tc.shown + `"`,
				`invalid URL escape "%zz"`,
			} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.creds {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
				}
			}
			if strings.Contains(fail.Reason, "invalid percent escape in its userinfo") {
				t.Fatalf("a base-path escape must not be mislabeled a userinfo error: %q", fail.Reason)
			}
		})
	}
}

// TestResolveCLISchemelessSchemeTextInPathLegalStillRejected pins that a
// fully legal leading-"//" address (legal credentials, scheme text merely in
// the path) is still rejected for the missing scheme, is never promoted and
// keeps its credentials out of the reason.
func TestResolveCLISchemelessSchemeTextInPathLegalStillRejected(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		hidden   []string
	}{
		{"encoded password", "//alice:p%40ss@api.internal/http://mirror/v1", []string{"alice", "p%40ss", "p@ss"}},
		{"username only", "//alice@api.internal/https://mirror/v1", []string{"alice"}},
		{"no userinfo", "//api.internal/http://mirror/v1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"reader","methods":["GET"],"pathPrefix":"/reader","upstream":"` + tc.upstream + `"}]}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/reader/items"}`)
			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want empty", res.stdout)
			}
			var fail struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{"route 1", `"reader"`, "upstream", "upstream must be an absolute http or https URL"} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
				}
			}
			for _, scheme := range []string{"http://", "https://"} {
				// The reason's fixed wording contains no scheme marker at all.
				if strings.Contains(fail.Reason, scheme) {
					t.Fatalf("reason = %q must not add a scheme", fail.Reason)
				}
			}
		})
	}
}
