package contractsentinel

import (
	"strings"
	"testing"
)

// These tests pin the credential-redaction boundary when a schemeless
// upstream's base path itself contains scheme text — an address such as
// "//alice:pw%4@api.internal/http://mirror/v1". The leading "//" alone
// decides that the address has no scheme: the "http://" after the first
// path slash is base-path content and must not be mistaken for the scheme
// separator, which would place the authority boundary on the wrong slash,
// drop the userinfo into the path and let the username, password and the
// malformed credential fragment pass into the diagnostic unredacted. The
// address stays schemeless and rejected, its userinfo is hidden whole, and
// a base-path error keeps its own diagnostic exactly as for a path without
// scheme text.

// schemelessPathSchemeConfig builds a one-route config whose id is reader.
func schemelessPathSchemeConfig(upstream string) string {
	return `{"routes":[{"id":"reader","methods":["GET"],"pathPrefix":"/reader","upstream":"` + upstream + `"}]}`
}

// TestSchemelessUpstreamSchemeTextInPathBadUserinfo drives the headline
// case: //alice:pw%4@api.internal/http://mirror/v1 carries a truncated
// escape in the password and a literal "http://" in the base path. The
// path text must not be read as the scheme: the failure is the dedicated
// userinfo-escape reason, the address is shown only as
// "//***@api.internal/http://mirror/v1" (the path, "http://" included, is
// kept), and neither credential — original or decoded — nor the "%4"
// fragment may appear anywhere.
func TestSchemelessUpstreamSchemeTextInPathBadUserinfo(t *testing.T) {
	upstream := "//alice:pw%4@api.internal/http://mirror/v1"
	cfg, f := ParseConfig([]byte(schemelessPathSchemeConfig(upstream)))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}
	for _, want := range []string{
		"route 1",
		`"reader"`,
		"upstream",
		"invalid percent escape in its userinfo",
		`"//***@api.internal/http://mirror/v1"`,
	} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", "p@", `"%4"`, "//alice"} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential %q", f.Reason, leaked)
		}
	}
	if strings.Contains(f.Reason, "not valid JSON") {
		t.Fatalf("a schemeless upstream is a content error, not a JSON syntax failure: %q", f.Reason)
	}
}

// TestSchemelessUpstreamSchemeTextInPathPathError pins that legal
// credentials plus a malformed escape in the base path keep the base-path
// diagnostic even when the path spells a scheme:
// //alice:p%40ss@api.internal/https://mirror/%zz must hide the credentials
// whole while keeping the host, the full base path (the "https://" text
// included) and the `invalid URL escape "%zz"` fragment, and must not be
// mislabeled a userinfo error.
func TestSchemelessUpstreamSchemeTextInPathPathError(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{
			name:     "bad escape after scheme text in path",
			upstream: "//alice:p%40ss@api.internal/https://mirror/%zz",
			shown:    "//***@api.internal/https://mirror/%zz",
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "at sign in path stays path content",
			upstream: "//alice:p%40ss@api.internal/https://mirror/v1@x/%zz",
			shown:    "//***@api.internal/https://mirror/v1@x/%zz",
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "http text in path with username-only userinfo",
			upstream: "//alice@api.internal/http://mirror/%zz",
			shown:    "//***@api.internal/http://mirror/%zz",
			hidden:   []string{"alice"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := ParseConfig([]byte(schemelessPathSchemeConfig(tc.upstream)))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
			for _, want := range []string{
				"route 1",
				`"reader"`,
				"upstream",
				"not a valid URL",
				`parse "` + tc.shown + `"`,
				`invalid URL escape "%zz"`,
				"api.internal",
			} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", f.Reason, leaked)
				}
			}
			if strings.Contains(f.Reason, "invalid percent escape in its userinfo") {
				t.Fatalf("a base-path escape must not be mislabeled a userinfo error: %q", f.Reason)
			}
		})
	}
}

// TestSchemelessUpstreamSchemeTextInPathLegalStillRejected pins that when
// every part of a leading-"//" address is legal apart from the missing
// scheme — scheme text in the base path included — it is still rejected by
// the absolute http/https rule, never promoted, and the reason neither
// quotes the address (so the credentials stay hidden) nor gains a scheme.
func TestSchemelessUpstreamSchemeTextInPathLegalStillRejected(t *testing.T) {
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
			cfg, f := ParseConfig([]byte(schemelessPathSchemeConfig(tc.upstream)))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
			if !strings.Contains(f.Reason, "upstream must be an absolute http or https URL") {
				t.Fatalf("reason = %q, want the absolute http/https rule", f.Reason)
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", f.Reason, leaked)
				}
			}
			// The missing-scheme reason must not quote the address, and must
			// not render a "://" marker the configured address did not have.
			if strings.Contains(f.Reason, `"//`) {
				t.Fatalf("reason = %q must not quote the schemeless address", f.Reason)
			}
		})
	}
}

// TestSchemelessUpstreamSchemeTextInPathRejectsWholeConfig pins that the
// bad route fails the whole read even though the request would only hit an
// earlier, legal route: no config comes back and the reason locates the
// later route with its credentials hidden.
func TestSchemelessUpstreamSchemeTextInPathRejectsWholeConfig(t *testing.T) {
	src := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"reader","methods":["GET"],"pathPrefix":"/reader","upstream":"//alice:pw%4@api.internal/http://mirror/v1"}
	]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("the whole config must be rejected even though /api only hits route 1, got %+v", cfg)
	}
	for _, want := range []string{
		"route 2",
		`"reader"`,
		"upstream",
		"invalid percent escape in its userinfo",
		`"//***@api.internal/http://mirror/v1"`,
	} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", `"%4"`} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", f.Reason, leaked)
		}
	}
}

// TestSplitUpstreamSchemeTextInPath pins the boundary decision itself: a
// leading "//" always marks a schemeless address regardless of later
// "://" text, while a real scheme keeps its marker even when the base
// path also contains one.
func TestSplitUpstreamSchemeTextInPath(t *testing.T) {
	cases := []struct {
		name           string
		raw            string
		schemeEnd      int
		authorityStart int
		authority      string
		hostPort       string
		basePath       string
	}{
		{
			name:           "schemeless with http text in base path",
			raw:            "//alice:pw%4@api.internal/http://mirror/v1",
			schemeEnd:      -1,
			authorityStart: 2,
			authority:      "alice:pw%4@api.internal",
			hostPort:       "api.internal",
			basePath:       "/http://mirror/v1",
		},
		{
			name:           "schemeless with https text in base path",
			raw:            "//alice:p%40ss@api.internal/https://mirror/%zz",
			schemeEnd:      -1,
			authorityStart: 2,
			authority:      "alice:p%40ss@api.internal",
			hostPort:       "api.internal",
			basePath:       "/https://mirror/%zz",
		},
		{
			name:           "schemeless without userinfo",
			raw:            "//api.internal/http://mirror",
			schemeEnd:      -1,
			authorityStart: 2,
			authority:      "api.internal",
			hostPort:       "api.internal",
			basePath:       "/http://mirror",
		},
		{
			name:           "schemeless plain address unchanged",
			raw:            "//host/base",
			schemeEnd:      -1,
			authorityStart: 2,
			authority:      "host",
			hostPort:       "host",
			basePath:       "/base",
		},
		{
			name:           "real https scheme keeps its marker with scheme text in path",
			raw:            "https://h.example/http://mirror/v1",
			schemeEnd:      5,
			authorityStart: 8,
			authority:      "h.example",
			hostPort:       "h.example",
			basePath:       "/http://mirror/v1",
		},
		{
			name:           "no authority marker at all",
			raw:            "api.internal/v1",
			schemeEnd:      -1,
			authorityStart: 0,
			authority:      "",
			hostPort:       "",
			basePath:       "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := splitUpstream(tc.raw)
			if p.schemeEnd != tc.schemeEnd || p.authorityStart != tc.authorityStart ||
				p.authority != tc.authority || p.hostPort != tc.hostPort || p.basePath != tc.basePath {
				t.Fatalf("splitUpstream(%q) = %+v, want schemeEnd=%d authorityStart=%d authority=%q hostPort=%q basePath=%q",
					tc.raw, p, tc.schemeEnd, tc.authorityStart, tc.authority, tc.hostPort, tc.basePath)
			}
		})
	}
}

// TestRedactUpstreamUserinfoSchemeTextInPath pins the redaction helper on
// addresses whose base path contains scheme text: only the authority
// userinfo is hidden; the path's "://" bytes and everything after the
// first path slash stay verbatim.
func TestRedactUpstreamUserinfoSchemeTextInPath(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"//alice:pw%4@api.internal/http://mirror/v1", "//***@api.internal/http://mirror/v1"},
		{"//alice:p%40ss@api.internal/https://mirror/%zz", "//***@api.internal/https://mirror/%zz"},
		{"//alice@api.internal/https://mirror/v1@x", "//***@api.internal/https://mirror/v1@x"},
		{"//api.internal/http://mirror/v1", "//api.internal/http://mirror/v1"},
		{"https://alice:s3cr%40t@h.example/v1/http://mirror/x", "https://***@h.example/v1/http://mirror/x"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := redactUpstreamUserinfo(tc.raw); got != tc.want {
				t.Fatalf("redactUpstreamUserinfo(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestSchemeBearingUpstreamWithSchemeTextInPathUnchanged pins the success
// contract: a legal absolute https upstream whose base path itself contains
// "://" is accepted, and resolving keeps the credentials, their percent
// encoding and the path text byte for byte.
func TestSchemeBearingUpstreamWithSchemeTextInPathUnchanged(t *testing.T) {
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"https://alice:s3cr%40t@host.internal/v1/http://mirror/x"}]}`
	cfg := mustConfig(t, src)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/ping"}`)
	if want := "https://alice:s3cr%40t@host.internal/v1/http://mirror/x/ping"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}
