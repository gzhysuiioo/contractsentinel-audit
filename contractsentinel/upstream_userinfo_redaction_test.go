package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests pin the credential redaction of upstream diagnostics: when a
// configuration error reason quotes an upstream address that carries
// userinfo, the whole userinfo segment — username and optional password,
// colons and percent escapes included — is replaced by "***" while the '@'
// separating it from the host is kept, so a saved diagnostic can never leak
// the configured credentials. The reason still names the route's 1-based
// position, its id, the upstream field and the actual problem, the code
// stays invalid_config and the whole config is still rejected.

// TestUpstreamUserinfoRedactedInMissingHostReason drives the headline case:
// "https://alice:s3cr%40t@:8443/v1" fails the missing-host check, and the
// reason must show the address as "https://***@:8443/v1" — never the
// username, never the password, encoded or decoded.
func TestUpstreamUserinfoRedactedInMissingHostReason(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string   // the address as it must appear in the reason
		hidden   []string // byte sequences that must not appear anywhere
	}{
		{"encoded password", "https://alice:s3cr%40t@:8443/v1", "https://***@:8443/v1", []string{"alice", "s3cr%40t", "s3cr@t"}},
		{"plain userinfo", "http://alice:secret@:8080/base", "http://***@:8080/base", []string{"alice", "secret"}},
		{"username only", "http://alice@:8080/base", "http://***@:8080/base", []string{"alice"}},
		{"empty password", "http://alice:@:8080/base", "http://***@:8080/base", []string{"alice"}},
		{"colons in password", "http://alice:s3:cr3t@:8080/base", "http://***@:8080/base", []string{"alice", "s3:cr3t"}},
		{"multiple at signs in authority", "https://al@ice:s3cr%40t@:8443/v1", "https://***@:8443/v1", []string{"al@ice", "s3cr%40t"}},
		{"at sign in base path is not userinfo", "https://alice:pw9@:8443/v1@x", "https://***@:8443/v1@x", []string{"alice", "pw9"}},
		{"userinfo reduced to empty authority", "http://svc@/base", "http://***@/base", []string{"svc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
			  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"` + tc.upstream + `"}
			]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", tc.upstream, cfg, f)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
			for _, want := range []string{"route 2", `"admin"`, "upstream", "missing a host", `"` + tc.shown + `"`} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks userinfo %q", f.Reason, leaked)
				}
			}
		})
	}
}

// TestUpstreamUserinfoRedactedInHostAndParseReasons covers the other
// diagnostics that quote the address: the extra-colon host rule and the
// generic URL parse error (an invalid escape). The attached parse error
// must not repeat the original address either.
func TestUpstreamUserinfoRedactedInHostAndParseReasons(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		want     []string
		hidden   []string
	}{
		{
			name:     "extra colon after userinfo",
			upstream: "https://alice:s3:cr3t@api:internal:8080/base",
			want:     []string{"route 1", `"api"`, "upstream", "more than one colon", `"https://***@api:internal:8080/base"`},
			hidden:   []string{"alice", "s3:cr3t"},
		},
		{
			name:     "invalid escape in userinfo",
			upstream: "https://alice:p%4@host.internal/",
			want:     []string{"route 1", `"api"`, "upstream", "invalid percent escape in its userinfo", `"https://***@host.internal/"`},
			hidden:   []string{"alice", "p%4", `"%4"`},
		},
		{
			name:     "invalid escape in host with userinfo",
			upstream: "https://alice:secret@ho%zzst/",
			want:     []string{"route 1", `"api"`, "upstream", "not a valid URL", `parse "https://***@ho%zzst/"`},
			hidden:   []string{"alice", "secret"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", tc.upstream, cfg, f)
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks userinfo %q", f.Reason, leaked)
				}
			}
		})
	}
}

// TestUpstreamWithoutUserinfoKeepsExistingDiagnostics pins that an address
// without userinfo is shown in full exactly as before — redaction must not
// rewrite diagnostics that carry no credentials.
func TestUpstreamWithoutUserinfoKeepsExistingDiagnostics(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		want     string
	}{
		{"bare port", "http://:8080/base", `upstream "http://:8080/base" is missing a host`},
		{"at sign only in base path", "http://:8080/v1@x", `upstream "http://:8080/v1@x" is missing a host`},
		{"extra colon", "http://api:internal:8080/base", `upstream "http://api:internal:8080/base" has an unbracketed host part`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
			_, f := ParseConfig([]byte(src))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got %+v, want invalid_config", tc.upstream, f)
			}
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.want)
			}
			if strings.Contains(f.Reason, "***") {
				t.Fatalf("reason = %q must not redact an address without userinfo", f.Reason)
			}
		})
	}
}

// TestValidUserinfoUpstreamUnchanged pins that redaction only touches
// failure diagnostics: a legal upstream with userinfo is still accepted,
// the resolved upstreamURL keeps the original address byte for byte
// (percent escapes included) and the stored config keeps the userinfo.
func TestValidUserinfoUpstreamUnchanged(t *testing.T) {
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"https://alice:s3cr%40t@host.internal:8443/v1"}]}`
	cfg := mustConfig(t, src)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/x"}`)
	if want := "https://alice:s3cr%40t@host.internal:8443/v1/x"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
	if cfg.Routes[0].Upstream != "https://alice:s3cr%40t@host.internal:8443/v1" {
		t.Errorf("stored upstream = %q, want the original address with userinfo", cfg.Routes[0].Upstream)
	}
}

// TestUpstreamUserinfoBadEscapeDedicatedReason is the headline fix: when
// the password (or username) itself is an illegal percent escape such as
// https://alice:%zz@host.internal/base, url.Parse's reason would quote the
// credential verbatim (invalid URL escape "%zz"). The config reader must
// instead return invalid_config with a reason that locates the route by its
// 1-based position, id and the upstream field, shows the address as
// "scheme://***@host/..." (whole username and optional password hidden,
// '@' and the rest kept) and never repeats the malformed fragment or any
// other byte of the credential. No config is returned.
func TestUpstreamUserinfoBadEscapeDedicatedReason(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string   // redacted address that must appear quoted
		hidden   []string // bytes that must not appear anywhere in the reason
	}{
		{"illegal escape in password", "https://alice:%zz@host.internal/base", "https://***@host.internal/base", []string{"alice", "%zz", `"%zz"`}},
		{"truncated escape at password end", "https://alice:pw%2@host.internal/base", "https://***@host.internal/base", []string{"alice", "pw%2", `"%2"`}},
		{"truncated escape mid password", "https://alice:p%4@host.internal/", "https://***@host.internal/", []string{"alice", "p%4", `"%4"`}},
		{"lone percent in password", "https://alice:pw%@host/", "https://***@host/", []string{"alice", "pw%", `"%"`}},
		{"illegal escape in username with password", "https://%zz:secret@host.internal/base", "https://***@host.internal/base", []string{"secret", "%zz", `"%zz"`}},
		{"illegal escape in username only", "https://al%zz@host.internal/base", "https://***@host.internal/base", []string{"al%zz", `"%zz"`}},
		{"username-only truncated escape", "http://u%4@host/base", "http://***@host/base", []string{"u%4", `"%4"`}},
		{"empty password then bad username", "https://%zz:@host/", "https://***@host/", []string{"%zz", `"%zz"`}},
		{"uppercase scheme spelling", "HTTPS://alice:%zz@host/", "HTTPS://***@host/", []string{"alice", "%zz", `"%zz"`}},
		{"http scheme", "http://alice:%zz@host/", "http://***@host/", []string{"alice", "%zz", `"%zz"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", tc.upstream, cfg, f)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
			for _, want := range []string{"route 1", `"api"`, "upstream", "invalid percent escape in its userinfo", `"` + tc.shown + `"`} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential fragment %q", f.Reason, leaked)
				}
			}
		})
	}
}

// TestUpstreamUserinfoBadEscapeRejectsWholeConfig pins that a bad
// userinfo escape rejects the whole configuration even when the request
// only matches a different, legal route: ParseConfig hands back no config at
// all, and the reason locates the offending later route by its 1-based
// position and id.
func TestUpstreamUserinfoBadEscapeRejectsWholeConfig(t *testing.T) {
	src := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"https://alice:%zz@host.internal/base"}
	]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("the whole config must be rejected even though /api only hits route 1, got %+v", cfg)
	}
	for _, want := range []string{"route 2", `"admin"`, "upstream", `"https://***@host.internal/base"`} {
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

// TestUpstreamHostAndPathEscapesKeepTheirDiagnostics pins the other side of
// the redaction boundary: when the userinfo is legal and the malformed
// escape actually belongs to the host or base path, the existing specific
// diagnostic — including its fragment — is preserved verbatim, even when the
// host or path text is identical to a string that would be a credential,
// and an '@' inside the base path must not be read as userinfo. Only the
// credentials are hidden.
func TestUpstreamHostAndPathEscapesKeepTheirDiagnostics(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		keep     []string // diagnostics that must survive, fragment included
		hidden   []string // only the credentials are hidden
	}{
		{
			name:     "illegal escape in host with legal userinfo",
			upstream: "https://alice:secret@ho%zzst/",
			shown:    "https://***@ho%zzst/",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "secret"},
		},
		{
			name:     "illegal escape in base path with legal userinfo",
			upstream: "https://alice:pw9@host.internal/base%zz/x",
			shown:    "https://***@host.internal/base%zz/x",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "pw9"},
		},
		{
			name:     "at sign in base path is not userinfo",
			upstream: "https://alice:pw9@host.internal/v1@x%zz",
			shown:    "https://***@host.internal/v1@x%zz",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`, "/v1@x%zz"},
			hidden:   []string{"alice", "pw9"},
		},
		{
			name:     "illegal escape in host without userinfo stays whole",
			upstream: "http://ho%zzst/",
			shown:    "http://ho%zzst/",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   nil,
		},
		{
			name:     "illegal escape in base path without userinfo stays whole",
			upstream: "http://host.internal/base%zz/x",
			shown:    "http://host.internal/base%zz/x",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`, "host.internal"},
			hidden:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", tc.upstream, cfg, f)
			}
			if !strings.Contains(f.Reason, `parse "`+tc.shown+`"`) {
				t.Fatalf("reason = %q, want redacted address %q", f.Reason, tc.shown)
			}
			for _, want := range tc.keep {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want host/path diagnostic %q preserved", f.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", f.Reason, leaked)
				}
			}
		})
	}
}

// TestUpstreamUserinfoBadEscapeNonHTTPSchemeStillRedacted pins the
// defense-in-depth path: a non-http scheme with a bad userinfo escape keeps
// the generic "not a valid URL" wording (the dedicated field reason is the
// http/https contract) but still never quotes the credential fragment.
func TestUpstreamUserinfoBadEscapeNonHTTPSchemeStillRedacted(t *testing.T) {
	src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"ftp://alice:%zz@host.internal/base"}]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	for _, want := range []string{"not a valid URL", `parse "ftp://***@host.internal/base"`} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "%zz"} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential fragment %q", f.Reason, leaked)
		}
	}
}

// TestValidUserinfoUpstreamSurvivesSaveRoundTrip pins that diagnostic
// redaction never reaches persisted configuration: a legal credential is
// accepted and re-marshalled with the username, password and percent
// encoding byte for byte, and the re-parsed config resolves identically.
func TestValidUserinfoUpstreamSurvivesSaveRoundTrip(t *testing.T) {
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"https://alice:s3cr%40t@host.internal/v1"}]}`
	cfg := mustConfig(t, src)
	saved, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(saved), `"upstream":"https://alice:s3cr%40t@host.internal/v1"`) {
		t.Fatalf("saved config lost userinfo or percent encoding: %s", saved)
	}
	reparsed := mustConfig(t, string(saved))
	res := resolveJSON(t, reparsed, `{"method":"GET","target":"/x"}`)
	if want := "https://alice:s3cr%40t@host.internal/v1/x"; res.UpstreamURL != want {
		t.Fatalf("reparsed upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}
