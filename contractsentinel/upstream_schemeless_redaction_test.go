package contractsentinel

import (
	"strings"
	"testing"
)

// These tests pin credential hiding on the failure diagnostics of a
// schemeless upstream written as a protocol-relative reference: an address
// that starts with "//" and carries no scheme, e.g.
// "//alice:pw%4@api.internal/v1". Such an upstream is always rejected — the
// reader never completes it to http or https — but the rejection reason
// quotes the address, so the whole userinfo segment (username and optional
// password) must be replaced by "***" there exactly as it is for an
// absolute upstream: the address may only ever read
// "//***@api.internal/v1", with the '@', host, port and base path kept and
// neither the raw nor the decoded credentials anywhere in the reason.

// parseSchemelessRoute is the one fixture builder the cases share: one
// syntactically valid route object (so a failure can never be a JSON syntax
// failure) whose upstream is the raw schemeless spelling.
func parseSchemelessRoute(t *testing.T, upstream string) (*Config, *Failure) {
	t.Helper()
	src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + upstream + `"}]}`
	return ParseConfig([]byte(src))
}

// assertCredentialFreeUserinfoReason is the shared contract every
// schemeless failure reason below must satisfy: the code is
// invalid_config, no config comes back, the route is located by its
// 1-based position, its non-empty id and the upstream field, the document
// is never called broken JSON, and neither the raw nor the decoded
// credentials (nor any individually quoted credential fragment) occur
// anywhere in the reason. When shown is non-empty the redacted address
// must additionally appear quoted in exactly that shape (some host rules
// quote only the offending host part, so their callers pass "" and assert
// the address themselves).
func assertCredentialFreeUserinfoReason(t *testing.T, f *Failure, cfg *Config, routePos, id, shown string, hidden []string) {
	t.Helper()
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}
	wantSubs := []string{routePos, `"` + id + `"`, "upstream"}
	if shown != "" {
		wantSubs = append(wantSubs, `"`+shown+`"`)
	}
	for _, want := range wantSubs {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	if strings.Contains(f.Reason, "not valid JSON") {
		t.Fatalf("a schemeless upstream is a content error in legal JSON, reason = %q", f.Reason)
	}
	for _, leaked := range hidden {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential text %q", f.Reason, leaked)
		}
	}
}

// TestSchemelessUpstreamRejectedAndRedacted is the headline fix:
// "//alice:pw%4@api.internal/v1" is rejected (no scheme is ever added) and
// its reason may show the address only as "//***@api.internal/v1". The
// truncated "%4" lives in the password, so the reason must point at the
// userinfo without quoting the bad fragment or any other credential byte.
func TestSchemelessUpstreamRejectedAndRedacted(t *testing.T) {
	cfg, f := parseSchemelessRoute(t, "//alice:pw%4@api.internal/v1")
	assertCredentialFreeUserinfoReason(t, f, cfg, "route 1", "api",
		"//***@api.internal/v1",
		[]string{"alice", "pw%4", "pwa", `"%4"`})
}

// TestSchemelessUserinfoRedactionShapes covers the two ways a schemeless
// address with credentials fails: a reason that quotes the address renders
// it as "//***@..." (missing host, a parse error, ...), while the terminal
// missing-scheme rule — reached by an address that otherwise parses — keeps
// its existing generic wording and simply never echoes the address; either
// way the route is located and neither credential byte may appear.
func TestSchemelessUserinfoRedactionShapes(t *testing.T) {
	cases := []struct {
		name          string
		upstream      string
		shown         string // "" when the winning reason does not quote the address
		ruleSubstring string // text identifying the winning reason
		hidden        []string
	}{
		{"missing host after userinfo", "//svc@/v1", "//***@/v1", "missing a host", []string{"svc"}},
		{"username and password, missing scheme", "//alice:secret@api.internal:8080/v1", "", "absolute http or https URL", []string{"alice", "secret"}},
		{"username only, missing scheme", "//alice@api.internal/v1", "", "absolute http or https URL", []string{"alice"}},
		{"empty password, missing scheme", "//alice:@api.internal/v1", "", "absolute http or https URL", []string{"alice"}},
		{"colons in password, missing scheme", "//alice:s3:cr3t@api.internal/v1", "", "absolute http or https URL", []string{"alice", "s3:cr3t"}},
		{"multiple at signs in authority", "//al@ice:p%40w@api.internal/v1", "", "absolute http or https URL", []string{"al@ice", "p%40w", "p@w"}},
		{"no base path, missing scheme", "//alice:secret@api.internal", "", "absolute http or https URL", []string{"alice", "secret"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := parseSchemelessRoute(t, tc.upstream)
			assertCredentialFreeUserinfoReason(t, f, cfg, "route 1", "api", tc.shown, tc.hidden)
			if !strings.Contains(f.Reason, tc.ruleSubstring) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.ruleSubstring)
			}
			if tc.shown == "" && strings.Contains(f.Reason, "***") {
				t.Fatalf("the generic missing-scheme reason must not echo the address at all: %q", f.Reason)
			}
		})
	}
}

// TestSchemelessBadUserinfoEscapeHiddenInEveryShape pins that an illegal
// percent escape in the username or password of a schemeless address is
// attributed to the userinfo with a fixed, fragment-free phrase: the
// reason never quotes "%zz", "%4", "%" or any decoded credential byte,
// while the host and base path stay visible.
func TestSchemelessBadUserinfoEscapeHiddenInEveryShape(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{"illegal escape in password", "//alice:%zz@host.internal/base", "//***@host.internal/base", []string{"alice", "%zz", `"%zz"`}},
		{"truncated escape at password end", "//alice:pw%2@host.internal/base", "//***@host.internal/base", []string{"alice", "pw%2", `"%2"`}},
		{"truncated escape mid password", "//alice:p%4@host.internal/", "//***@host.internal/", []string{"alice", "p%4", `"%4"`}},
		{"lone percent in password", "//alice:pw%@host/", "//***@host/", []string{"alice", "pw%", `"%"`}},
		{"illegal escape in username with password", "//%zz:secret@host.internal/base", "//***@host.internal/base", []string{"secret", "%zz", `"%zz"`}},
		{"illegal escape in username only", "//al%zz@host.internal/base", "//***@host.internal/base", []string{"al%zz", `"%zz"`}},
		{"username only truncated escape", "//u%4@host/base", "//***@host/base", []string{"u%4", `"%4"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := parseSchemelessRoute(t, tc.upstream)
			assertCredentialFreeUserinfoReason(t, f, cfg, "route 1", "api", tc.shown, tc.hidden)
			if !strings.Contains(f.Reason, "userinfo") {
				t.Fatalf("reason = %q, want the problem located in the userinfo", f.Reason)
			}
		})
	}
}

// TestSchemelessPathEscapeKeepsPathDiagnostic pins the redaction boundary
// on the base path: when the userinfo is legal and a malformed escape
// belongs to the base path, the credentials are hidden but the path
// diagnostic — including the "%zz" fragment — survives, and an '@' in the
// base path is just a path byte that must not widen the hidden range.
func TestSchemelessPathEscapeKeepsPathDiagnostic(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		keep     []string
		hidden   []string
	}{
		{
			name:     "bad path escape after legal credentials",
			upstream: "//alice:p%40ss@api.internal/%zz",
			shown:    "//***@api.internal/%zz",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "at sign in base path is not userinfo",
			upstream: "//alice:pw9@host.internal/v1@x%zz",
			shown:    "//***@host.internal/v1@x%zz",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`, "/v1@x%zz"},
			hidden:   []string{"alice", "pw9"},
		},
		{
			name:     "bad path escape deeper in the path",
			upstream: "//alice:pw9@host.internal/base%zz/x",
			shown:    "//***@host.internal/base%zz/x",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "pw9"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := parseSchemelessRoute(t, tc.upstream)
			assertCredentialFreeUserinfoReason(t, f, cfg, "route 1", "api", tc.shown, tc.hidden)
			for _, want := range tc.keep {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want path diagnostic %q preserved", f.Reason, want)
				}
			}
		})
	}
}

// TestSchemelessHostErrorsKeepHostDiagnostic pins the other side of the
// boundary: a host-side problem keeps its host-specific wording and the
// host bytes; only the credentials are hidden. The error selection order
// is the same one an absolute spelling uses, so a host error that precedes
// the userinfo stage in net/url is still the reported reason rather than a
// generic credential complaint.
func TestSchemelessHostErrorsKeepHostDiagnostic(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		keep     []string
		hidden   []string
	}{
		{
			name:     "bad host escape after legal credentials",
			upstream: "//alice:secret@ho%zzst/",
			shown:    "//***@ho%zzst/",
			keep:     []string{"not a valid URL", `parse "//***@ho%zzst/"`, `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "secret"},
		},
		{
			name:     "extra colon host after credentials",
			upstream: "//alice:s3:cr3t@api:internal:8080/base",
			shown:    "//***@api:internal:8080/base",
			keep:     []string{"more than one colon", `"api:internal:8080"`},
			hidden:   []string{"alice", "s3:cr3t"},
		},
		{
			name: "bad bracketed host after credentials",
			// The bracket rule quotes only the offending host literal (never
			// the credentials), so no whole-address rendering is asserted
			// here; the host wording and the hidden credentials are the
			// boundary under test.
			upstream: "//alice:secret@[not-an-ip]:8080/",
			shown:    "",
			keep:     []string{"in brackets", "IPv6", `"not-an-ip"`},
			hidden:   []string{"alice", "secret"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := parseSchemelessRoute(t, tc.upstream)
			assertCredentialFreeUserinfoReason(t, f, cfg, "route 1", "api", tc.shown, tc.hidden)
			for _, want := range tc.keep {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want host diagnostic %q preserved", f.Reason, want)
				}
			}
		})
	}
}

// TestSchemelessUpstreamRejectsWholeConfig pins that one bad schemeless
// route fails the whole read even when the request would only hit another,
// legal http route: ParseConfig returns no config and the reason locates
// the offending later route by its 1-based position and id.
func TestSchemelessUpstreamRejectsWholeConfig(t *testing.T) {
	src := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"//alice:pw%4@api.internal/v1"}
	]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("the whole config must be rejected even though a request only hits route 1, got %+v", cfg)
	}
	for _, want := range []string{"route 2", `"admin"`, "upstream", `"//***@api.internal/v1"`} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", "pwa", "%4"} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", f.Reason, leaked)
		}
	}
}

// TestSchemelessUpstreamNeverCompletesAScheme pins that rejection is the
// only outcome: an otherwise well-shaped "//host/base" is never accepted,
// never saved and never resolved as http:// or https://, while a genuinely
// relative reference without "//" keeps its existing generic rejection.
func TestSchemelessUpstreamNeverCompletesAScheme(t *testing.T) {
	for _, upstream := range []string{
		"//api.internal/v1",
		"//alice:secret@api.internal/v1",
		"//:8080/base",
	} {
		cfg, f := parseSchemelessRoute(t, upstream)
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", upstream, cfg, f)
		}
		if cfg != nil {
			t.Fatalf("upstream %q must not be accepted or completed to a scheme", upstream)
		}
		if !strings.Contains(f.Reason, "upstream") {
			t.Fatalf("upstream %q: reason = %q must name the upstream field", upstream, f.Reason)
		}
		// The configured address must never reappear with a scheme prepended
		// (the reason's own example host is a different address).
		for _, completed := range []string{"http:" + upstream, "https:" + upstream} {
			if strings.Contains(f.Reason, completed) {
				t.Fatalf("upstream %q must not be completed in the reason: %q", upstream, f.Reason)
			}
		}
	}

	// A relative reference without the leading "//" keeps its existing
	// generic absolute-URL wording and is not run through the "//" rules.
	_, f := parseSchemelessRoute(t, "path/upstream")
	if f == nil || !strings.Contains(f.Reason, "absolute http or https") {
		t.Fatalf("relative reference reason = %+v, want the existing absolute-URL wording", f)
	}
}

// TestAbsoluteUserinfoBehaviorUnchanged guards the regression surface:
// legal http/https upstreams with userinfo still parse, resolve and keep
// their credentials and percent encoding byte for byte (hiding only ever
// touches failure diagnostics), and the http/https dedicated bad-userinfo
// reason keeps its wording.
func TestAbsoluteUserinfoBehaviorUnchanged(t *testing.T) {
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"https://alice:s3cr%40t@host.internal:8443/v1"}]}`
	cfg := mustConfig(t, src)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/x"}`)
	if want := "https://alice:s3cr%40t@host.internal:8443/v1/x"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// The dedicated http/https reason is unchanged for an absolute address.
	_, f := parseSchemelessRoute(t, "https://alice:%zz@host.internal/base")
	if f == nil {
		t.Fatal("want invalid_config for the bad absolute userinfo escape")
	}
	for _, want := range []string{"invalid percent escape in its userinfo", `"https://***@host.internal/base"`} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
}
