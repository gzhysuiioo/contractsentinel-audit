package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests pin the fix for a credential leak that survived the address
// redaction: when an http/https upstream carries userinfo (a username or
// password before the host) and parsing fails because a percent escape in
// that userinfo is illegal, url.Parse's reason quotes the offending escape
// itself ("invalid URL escape "%zz""), and the escape IS the configured
// password. The read must still return invalid_config with no usable
// config, locate the route by its 1-based position, id and the upstream
// field, show the address with its whole userinfo replaced by "***" (the
// '@' kept), and explain the userinfo escape problem in words that carry
// none of the username's or password's bytes. Escapes that are illegal in
// the host or base path keep their existing, specific diagnostic, and an
// '@' in the base path never counts as userinfo.

// configWithUpstream builds a two-route document whose second route carries
// the given upstream; the first route is valid and is the one a request
// would hit.
func configWithUpstream(upstream string) string {
	return `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"` + upstream + `"}
	]}`
}

// TestUserinfoInvalidEscapeRejectsConfig drives the headline case and the
// other shapes an illegal credential escape can take. Each configuration
// must come back as invalid_config with no config, a reason that locates
// route 2, its id and the upstream field and explains the userinfo escape,
// and a reason that contains none of the credential bytes — the address is
// masked and the offending escape fragment never appears in the prose.
func TestUserinfoInvalidEscapeRejectsConfig(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string   // the address exactly as it must appear quoted
		hidden   []string // byte sequences that must not occur anywhere
	}{
		{
			name:     "headline non hex escape in password",
			upstream: "https://alice:%zz@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice", "%zz"},
		},
		{
			name:     "illegal escape embedded in a password",
			upstream: "https://alice:secret%zzword@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice", "secret%zzword", "%zz"},
		},
		{
			name:     "truncated escape at the end of the password",
			upstream: "https://alice:p%4@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice", "p%4", "%4"},
		},
		{
			name:     "escape with one hex digit",
			upstream: "http://alice:p%2z@host.internal/base",
			shown:    "http://***@host.internal/base",
			hidden:   []string{"alice", "%2z"},
		},
		{
			name:     "uppercase second nibble is still illegal",
			upstream: "http://alice:p%ZZ@host.internal/base",
			shown:    "http://***@host.internal/base",
			hidden:   []string{"alice", "%ZZ"},
		},
		{
			name:     "lone percent as the password",
			upstream: "https://alice:%@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice"},
		},
		{
			name:     "trailing percent in the password",
			upstream: "https://alice:100%@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice", "100%"},
		},
		{
			name:     "illegal escape in the username, username only userinfo",
			upstream: "http://a%zzb@host.internal/base",
			shown:    "http://***@host.internal/base",
			hidden:   []string{"a%zzb", "%zz"},
		},
		{
			name:     "empty username, illegal escape in the password",
			upstream: "http://:%zz@host.internal/base",
			shown:    "http://***@host.internal/base",
			hidden:   []string{"%zz"},
		},
		{
			name:     "empty password field after an illegal username escape",
			upstream: "http://u%zz:@host.internal/base",
			shown:    "http://***@host.internal/base",
			hidden:   []string{"u%zz", "%zz"},
		},
		{
			name:     "multiple at signs keep the last as the host boundary",
			upstream: "https://al@ice:p%zz@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"al@ice", "p%zz", "%zz"},
		},
		{
			name:     "illegal userinfo escape with an explicit port and path",
			upstream: "https://alice:%zz@host.internal:8443/v1/x",
			shown:    "https://***@host.internal:8443/v1/x",
			hidden:   []string{"alice", "%zz"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := ParseConfig([]byte(configWithUpstream(tc.upstream)))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", tc.upstream, cfg, f)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
			for _, want := range []string{
				"route 2",
				`"admin"`,
				"upstream",
				"userinfo",
				"percent",
				`"` + tc.shown + `"`,
			} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential fragment %q", f.Reason, leaked)
				}
			}
			// The userinfo-specific failure is a content error, never the
			// generic parse wording, and never quotes any escape the way
			// url.Parse's "invalid URL escape %q" does.
			if strings.Contains(f.Reason, "invalid URL escape") {
				t.Fatalf("reason must explain the userinfo escape in words, not quote url.Parse's escape: %q", f.Reason)
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("an illegal credential escape is a content error, not a JSON syntax failure: %q", f.Reason)
			}
		})
	}
}

// TestUserinfoInvalidEscapeRejectsUnmatchedRoute pins that route matching is
// never consulted while the config is read: the offending route is route 2
// under /admin, which a request could never hit, and ParseConfig has no
// request at all — the whole document is still rejected with no config.
func TestUserinfoInvalidEscapeRejectsUnmatchedRoute(t *testing.T) {
	src := configWithUpstream("https://alice:%zz@host.internal/base")
	cfg, f := ParseConfig([]byte(src))
	if cfg != nil || f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want no config and invalid_config", cfg, f)
	}
	// A config that fails to read cannot resolve anything: even a request
	// for the valid first route has no Config to run against.
	if !strings.Contains(f.Reason, "route 2") || !strings.Contains(f.Reason, `"admin"`) {
		t.Fatalf("reason must locate the unmatched offending route: %q", f.Reason)
	}
}

// TestNonUserinfoEscapesKeepSpecificDiagnostics pins the masking boundary:
// only userinfo credentials are hidden. An illegal escape in the host or
// base path keeps url.Parse's verbatim escape text so the diagnosis stays
// specific, even when the same bytes also appear in credentials and even
// when a legal credential escape spells a prefix of the offending fragment
// (a "%40" password must not swallow a "%4" reported from the path).
func TestNonUserinfoEscapesKeepSpecificDiagnostics(t *testing.T) {
	cases := []struct {
		name      string
		upstream  string
		want      []string
		forbidden []string // must stay visible? no: these are masked-credential checks
		visible   []string // non-credential fragments that must remain visible
	}{
		{
			name:      "illegal escape in host with legal credentials",
			upstream:  "https://alice:secret@ho%zzst/",
			want:      []string{"route 2", `"admin"`, "upstream", "not a valid URL", `parse "https://***@ho%zzst/"`, `invalid URL escape "%zz"`},
			forbidden: []string{"alice", "secret"},
			visible:   []string{"ho%zzst", "%zz"},
		},
		{
			name:      "illegal escape in base path with legal credentials",
			upstream:  "https://alice:secret@host.internal/base%zz",
			want:      []string{"route 2", `"admin"`, "upstream", "not a valid URL", `parse "https://***@host.internal/base%zz"`, `invalid URL escape "%zz"`},
			forbidden: []string{"alice", "secret"},
			visible:   []string{"base%zz", "%zz"},
		},
		{
			name:      "illegal host escape without any userinfo is untouched",
			upstream:  "http://ho%zzst.internal/",
			want:      []string{"route 2", `"admin"`, "upstream", "not a valid URL", `parse "http://ho%zzst.internal/"`, `invalid URL escape "%zz"`},
			forbidden: []string{"***"},
			visible:   []string{"ho%zzst", "%zz"},
		},
		{
			name:      "illegal path escape without any userinfo is untouched",
			upstream:  "http://host.internal/base%zz/x",
			want:      []string{"route 2", `"admin"`, "upstream", "not a valid URL", `parse "http://host.internal/base%zz/x"`, `invalid URL escape "%zz"`},
			forbidden: []string{"***"},
			visible:   []string{"base%zz", "%zz"},
		},
		{
			name:      "an at sign in the base path is not userinfo",
			upstream:  "http://host.internal/v1@x/b%zz",
			want:      []string{"route 2", `"admin"`, "upstream", "not a valid URL", `parse "http://host.internal/v1@x/b%zz"`, `invalid URL escape "%zz"`, "v1@x"},
			forbidden: []string{"***"},
			visible:   []string{"v1@x", "b%zz"},
		},
		{
			name:      "at sign in base path coexists with real masked userinfo",
			upstream:  "https://alice:secret@host.internal/v1@x/b%zz",
			want:      []string{"route 2", `"admin"`, "upstream", `parse "https://***@host.internal/v1@x/b%zz"`, `invalid URL escape "%zz"`, "v1@x"},
			forbidden: []string{"alice", "secret"},
			visible:   []string{"v1@x", "b%zz"},
		},
		{
			name:      "legal %40 password does not mask a %4 error in the path",
			upstream:  "https://a:%40@host.internal/c%4@d",
			want:      []string{"route 2", `"admin"`, "upstream", "not a valid URL", `parse "https://***@host.internal/c%4@d"`, `invalid URL escape "%4@"`, "c%4@d"},
			forbidden: []string{"a:%40"},
			visible:   []string{"c%4@d", `"%4@"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, f := ParseConfig([]byte(configWithUpstream(tc.upstream)))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got %+v, want invalid_config", tc.upstream, f)
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, leaked := range tc.forbidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks/hides fragment %q", f.Reason, leaked)
				}
			}
			for _, frag := range tc.visible {
				if !strings.Contains(f.Reason, frag) {
					t.Fatalf("reason = %q must keep the non-credential fragment %q visible", f.Reason, frag)
				}
			}
		})
	}
}

// TestUserinfoEscapeRedactionDoesNotTouchLegalConfigs pins the success side:
// an upstream whose userinfo carries only legal percent escapes is read
// normally, resolves with the original address byte for byte and keeps the
// credentials and escapes in the stored config and in a save round trip.
func TestUserinfoEscapeRedactionDoesNotTouchLegalConfigs(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
	}{
		{"encoded at sign in password", "https://alice:s3cr%40t@host.internal:8443/v1"},
		{"lowercase encoded bytes", "http://alice:p%2f%2f@host.internal/base"},
		{"username only with encoded byte", "http://al%69ce@host.internal/base"},
		{"empty password", "http://alice:@host.internal/base"},
		{"percent forty in both components", "https://a%40:b%40@host.internal/base"},
		{"plain password stays plain", "https://alice:secret@host.internal/base"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"` + tc.upstream + `"}]}`
			cfg := mustConfig(t, src)
			if cfg.Routes[0].Upstream != tc.upstream {
				t.Fatalf("stored upstream = %q, want the original %q", cfg.Routes[0].Upstream, tc.upstream)
			}
			res := resolveJSON(t, cfg, `{"method":"GET","target":"/x"}`)
			if want := tc.upstream + "/x"; res.UpstreamURL != want {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
			}
			// The supported save path keeps the userinfo and its escapes.
			out, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal config: %v", err)
			}
			saved, f := ParseConfig(out)
			if f != nil {
				t.Fatalf("saved config must re-read as legal: %v\n%s", f, out)
			}
			if saved.Routes[0].Upstream != tc.upstream {
				t.Errorf("saved upstream = %q, want the original %q with credentials", saved.Routes[0].Upstream, tc.upstream)
			}
		})
	}
}

// TestUserinfoEscapeRedactionInResolveFallback covers the defense-in-depth
// path: joinUpstream re-parses the upstream of a Route built in-process,
// which never met ParseConfig's userinfo pre-check. Its fallback reason must
// still show the masked address and never quote the credential escape.
func TestUserinfoEscapeRedactionInResolveFallback(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "r", Methods: []string{"GET"}, PathPrefix: "/",
		Upstream: "https://alice:%zz@host.internal/base",
	}}}
	req, rf := ParseRequest([]byte(`{"method":"GET","target":"/x"}`))
	if rf != nil {
		t.Fatalf("unexpected request failure: %+v", rf)
	}
	res, f := Resolve(cfg, req)
	if res != nil {
		t.Fatalf("a bad in-process upstream must not resolve, got %+v", res)
	}
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got %+v, want invalid_config", f)
	}
	for _, want := range []string{`parse "https://***@host.internal/base"`, "userinfo"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "%zz"} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("fallback reason = %q leaks %q", f.Reason, leaked)
		}
	}
}

// TestNonHTTPSchemeUserinfoEscapeStillMasked pins that even outside the
// http/https dedicated rule, a credential-derived escape cannot survive in
// the generic url.Parse diagnostic: such an address is rejected and the
// address is masked with a generic userinfo explanation rather than the
// quoted password bytes.
func TestNonHTTPSchemeUserinfoEscapeStillMasked(t *testing.T) {
	_, f := ParseConfig([]byte(configWithUpstream("ftp://alice:%zz@host.internal/base")))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got %+v, want invalid_config", f)
	}
	for _, want := range []string{"route 2", `"admin"`, "upstream", `parse "ftp://***@host.internal/base"`, "userinfo"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "%zz"} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", f.Reason, leaked)
		}
	}
}
