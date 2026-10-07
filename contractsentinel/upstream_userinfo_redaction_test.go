package contractsentinel

import (
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
			want:     []string{"route 1", `"api"`, "upstream", "not a valid URL", `parse "https://***@host.internal/"`, "invalid URL escape"},
			hidden:   []string{"alice"},
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
