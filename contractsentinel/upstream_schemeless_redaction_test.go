package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests pin credential redaction for a schemeless upstream — an
// address written with a leading "//" and no scheme, e.g.
// "//alice:pw%4@api.internal/v1". Such an upstream is always rejected
// (never promoted to http or https), but its failure diagnostic must hide
// the whole username and optional password exactly like a scheme-bearing
// address: the address may only appear as "//***@host/...", the '@', host,
// port and base path are kept, and neither the original nor the decoded
// credential bytes may appear anywhere in the reason. A malformed escape in
// the userinfo is reported as a userinfo problem without quoting the bad
// fragment; a bad host or base path keeps its own diagnostic and its
// fragment, and the existing error-selection order is unchanged.

// schemelessRedactionCase is one upstream and the exact redacted address
// the reason must quote, alongside bytes that must never appear.
type schemelessRedactionCase struct {
	name     string
	upstream string
	shown    string
	hidden   []string
}

func schemelessConfig(upstream string) string {
	return `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + upstream + `"}]}`
}

// assertSchemelessRejected parses the one-route config, requires
// invalid_config with no config handed back, a route/id/upstream-located
// reason that never calls the legal JSON broken, and (when shown is set)
// the redacted address quoted in the reason with none of the hidden bytes.
func assertSchemelessRejected(t *testing.T, src, shown string, hidden []string) *Failure {
	t.Helper()
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}
	for _, want := range []string{"route 1", `"api"`, "upstream"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	if strings.Contains(f.Reason, "not valid JSON") {
		t.Fatalf("a schemeless upstream is a content error, not a JSON syntax failure: %q", f.Reason)
	}
	if shown != "" {
		if !strings.Contains(f.Reason, `"`+shown+`"`) {
			t.Fatalf("reason = %q, want the redacted address %q quoted", f.Reason, shown)
		}
	}
	for _, leaked := range hidden {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential %q", f.Reason, leaked)
		}
	}
	return f
}

// TestSchemelessUpstreamHeadlineRedaction drives the headline case:
// //alice:pw%4@api.internal/v1 fails the userinfo-escape content rule and
// must be shown only as //***@api.internal/v1.
func TestSchemelessUpstreamHeadlineRedaction(t *testing.T) {
	src := schemelessConfig("//alice:pw%4@api.internal/v1")
	f := assertSchemelessRejected(t, src, "//***@api.internal/v1",
		[]string{"alice", "pw%4", "p@", `"%4"`, "//alice"})
	for _, want := range []string{"invalid percent escape in its userinfo"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
}

// TestSchemelessUpstreamBadUserinfoEscapeDedicatedReason covers every
// malformed-credential shape: truncated and lone escapes, a bad username
// (with and without a password) and an empty password. The fixed reason
// names the userinfo and never quotes the offending fragment.
func TestSchemelessUpstreamBadUserinfoEscapeDedicatedReason(t *testing.T) {
	cases := []schemelessRedactionCase{
		{"illegal escape in password", "//alice:%zz@host.internal/base", "//***@host.internal/base", []string{"alice", "%zz", `"%zz"`}},
		{"truncated escape at password end", "//alice:pw%2@host.internal/base", "//***@host.internal/base", []string{"alice", "pw%2", `"%2"`}},
		{"truncated escape mid password", "//alice:p%4@host.internal/", "//***@host.internal/", []string{"alice", "p%4", `"%4"`}},
		{"lone percent in password", "//alice:pw%@host/", "//***@host/", []string{"alice", "pw%", `"%"`}},
		{"illegal escape in username with password", "//%zz:secret@host.internal/base", "//***@host.internal/base", []string{"secret", "%zz", `"%zz"`}},
		{"illegal escape in username only", "//al%zz@host.internal/base", "//***@host.internal/base", []string{"al%zz", `"%zz"`}},
		{"username only truncated escape", "//u%4@host/base", "//***@host/base", []string{"u%4", `"%4"`}},
		{"empty password then bad username", "//%zz:@host/", "//***@host/", []string{"%zz", `"%zz"`}},
		{"credential also carries an at sign text", "//al@ice:pw%4@host.internal/v1", "//***@host.internal/v1", []string{"al@ice", "pw%4"}},
		{"at sign in base path is not userinfo", "//alice:pw%4@host.internal/v1@x", "//***@host.internal/v1@x", []string{"alice", "pw%4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := assertSchemelessRejected(t, schemelessConfig(tc.upstream), tc.shown, tc.hidden)
			if !strings.Contains(f.Reason, "invalid percent escape in its userinfo") {
				t.Fatalf("reason = %q, want the dedicated userinfo reason", f.Reason)
			}
		})
	}
}

// TestSchemelessUpstreamLegalUserinfoStillRejectedSilently pins that a
// schemeless address with perfectly legal credentials is rejected for the
// missing scheme and the reason neither quotes the address (so it cannot
// leak the credentials) nor gains an http/https prefix.
func TestSchemelessUpstreamLegalUserinfoStillRejectedSilently(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		hidden   []string
	}{
		{"host and base path", "//alice:p%40ss@api.internal/v1", []string{"alice", "p%40ss", "p@ss"}},
		{"username only", "//alice@host.internal/base", []string{"alice"}},
		{"empty password", "//alice:@host.internal/base", []string{"alice"}},
		{"no userinfo", "//api.internal/v1", nil},
		{"bracketed ipv6 host", "//[2001:db8::1]/v1", nil},
		{"port and path", "//host.internal:8080/base", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := assertSchemelessRejected(t, schemelessConfig(tc.upstream), "", tc.hidden)
			if !strings.Contains(f.Reason, "upstream must be an absolute http or https URL") {
				t.Fatalf("reason = %q, want the absolute http/https rule", f.Reason)
			}
			// Redaction must never invent a scheme.
			for _, leaked := range []string{"http://", "https://", "HTTP://", "HTTPS://"} {
				if strings.Contains(f.Reason, leaked) {
					t.Fatalf("reason = %q must not add a scheme", f.Reason)
				}
			}
		})
	}
}

// TestSchemelessUpstreamHostAndPathDiagnosticsKept pins the redaction
// boundary: with legal credentials, a malformed escape that belongs to the
// host or base path keeps its own diagnostic and its fragment (so it is not
// mislabeled a password problem), while only the credentials are hidden. An
// '@' inside the base path stays a path character and never widens the
// hidden range.
func TestSchemelessUpstreamHostAndPathDiagnosticsKept(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		keep     []string
		hidden   []string
	}{
		{
			name:     "illegal escape in base path with legal userinfo",
			upstream: "//alice:p%40ss@api.internal/%zz",
			shown:    "//***@api.internal/%zz",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "illegal escape in host with legal userinfo",
			upstream: "//alice:secret@ho%zzst/",
			shown:    "//***@ho%zzst/",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "secret"},
		},
		{
			name:     "at sign in base path is path content",
			upstream: "//alice:pw9@host.internal/v1@x%zz",
			shown:    "//***@host.internal/v1@x%zz",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`, "/v1@x%zz"},
			hidden:   []string{"alice", "pw9"},
		},
		{
			name:     "illegal escape in host without userinfo stays whole",
			upstream: "//ho%zzst/",
			shown:    "//ho%zzst/",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   nil,
		},
		{
			name:     "illegal escape in base path without userinfo stays whole",
			upstream: "//host.internal/base%zz/x",
			shown:    "//host.internal/base%zz/x",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   nil,
		},
		{
			name:     "bad userinfo and host escapes together report the host first",
			upstream: "//alice:pw%4@ho%zzst/",
			shown:    "//***@ho%zzst/",
			keep:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			hidden:   []string{"alice", "pw%4", `"%4"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := assertSchemelessRejected(t, schemelessConfig(tc.upstream), tc.shown, tc.hidden)
			for _, want := range tc.keep {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want host/path diagnostic %q preserved", f.Reason, want)
				}
			}
			if strings.Contains(f.Reason, "invalid percent escape in its userinfo") {
				t.Fatalf("reason = %q must not mislabel a host/path error as a userinfo error", f.Reason)
			}
		})
	}
}

// TestSchemelessUpstreamHostValidatorsRedactUserinfo pins that the raw
// host validators — which now run for a schemeless "//" address too —
// each keep their own wording while any userinfo is hidden whole.
func TestSchemelessUpstreamHostValidatorsRedactUserinfo(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		want     string
		hidden   []string
	}{
		{
			name:     "missing host after userinfo",
			upstream: "//alice:s3cr%40t@:8443/v1",
			shown:    "//***@:8443/v1",
			want:     "missing a host",
			hidden:   []string{"alice", "s3cr%40t"},
		},
		{
			name:     "userinfo reduced to empty authority",
			upstream: "//svc@/base",
			shown:    "//***@/base",
			want:     "missing a host",
			hidden:   []string{"svc"},
		},
		{
			name:     "extra colon in host part after userinfo",
			upstream: "//alice:s3:cr3t@api:internal:8080/base",
			shown:    "//***@api:internal:8080/base",
			want:     "more than one colon",
			hidden:   []string{"alice", "s3:cr3t"},
		},
		{
			name:     "bracketed host is not an ipv6 literal",
			upstream: "//alice:secret@[not-an-ip]/x",
			shown:    "", // this reason quotes only the literal, not the address
			want:     "not a legal IPv6 address",
			hidden:   []string{"alice", "secret"},
		},
		{
			name:     "unbracketed ipv6 host missing brackets",
			upstream: "//alice:secret@2001:db8::1/",
			shown:    "",
			want:     "missing its square brackets",
			hidden:   []string{"alice", "secret"},
		},
		{
			name:     "port out of range",
			upstream: "//alice:x@h:99999/x",
			shown:    "",
			want:     "out of range",
			hidden:   []string{"alice"},
		},
		{
			name:     "direct space in base path",
			upstream: "//alice:x@h/base path",
			shown:    "",
			want:     "unencoded space",
			hidden:   []string{"alice"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := assertSchemelessRejected(t, schemelessConfig(tc.upstream), tc.shown, tc.hidden)
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want the %q diagnostic", f.Reason, tc.want)
			}
			if tc.shown != "" {
				// The address-quoting validators must hide the credentials;
				// reasons above that quote only a host fragment (bracketed
				// host, IPv6 literal, port, space) carry no address at all.
			}
		})
	}
}

// TestSchemelessUpstreamErrorSelectionOrderUnchanged pins that hiding
// credentials never changes which error is reported when the userinfo and
// the host or base path are both wrong: the host-shape and base-path rules
// keep preceding the url.Parse userinfo-escape attribution, exactly as for
// a scheme-bearing address.
func TestSchemelessUpstreamErrorSelectionOrderUnchanged(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		want     string
		hidden   []string
	}{
		{"bad bracket beats bad userinfo escape", "//alice:%zz@[not-an-ip]/x", "not a legal IPv6 address", []string{"alice", "%zz"}},
		{"out of range port beats bad userinfo escape", "//alice:%zz@h:99999/x", "out of range", []string{"alice", "%zz"}},
		{"missing host beats bad userinfo escape", "//alice:%zz@:8080/x", "missing a host", []string{"alice", "%zz"}},
		{"base path space beats bad userinfo escape", "//alice:%zz@h/base path", "unencoded space", []string{"alice", "%zz"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := assertSchemelessRejected(t, schemelessConfig(tc.upstream), "", tc.hidden)
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want the earlier %q diagnostic", f.Reason, tc.want)
			}
		})
	}
}

// TestSchemelessUpstreamRejectsWholeConfig pins that a schemeless upstream
// on a later route rejects the whole configuration even when the request
// only matches a different, legal route, and the reason locates the
// offending route by its 1-based position and id with the credentials
// hidden.
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
		t.Fatalf("the whole config must be rejected even though /api only hits route 1, got %+v", cfg)
	}
	for _, want := range []string{"route 2", `"admin"`, "upstream", "invalid percent escape in its userinfo", `"//***@api.internal/v1"`} {
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

// TestSchemelessUpstreamRejectedAfterSaveRoundTrip pins that the read
// interface is the gate a schemeless upstream cannot pass even after a
// save/re-read cycle: a marshalled document carrying one is rejected on
// re-parse with the same redacted diagnostic, while a legal https upstream
// with userinfo still round-trips with its credentials byte for byte.
func TestSchemelessUpstreamRejectedAfterSaveRoundTrip(t *testing.T) {
	bypassed := &Config{Routes: []Route{{
		ID: "r", Methods: []string{"GET"}, PathPrefix: "/", Upstream: "//alice:pw%4@host.internal/v1",
	}}}
	saved, err := json.Marshal(bypassed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(saved), "//alice:pw%4@host.internal/v1") {
		t.Fatalf("save keeps the configured bytes verbatim: %s", saved)
	}
	cfg, f := ParseConfig(saved)
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("re-parsing a saved schemeless upstream must fail, got cfg=%+v f=%+v", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("no config may be returned for a rejected document, got %+v", cfg)
	}
	if !strings.Contains(f.Reason, `"//***@host.internal/v1"`) {
		t.Fatalf("reason = %q, want the redacted address", f.Reason)
	}
	for _, leaked := range []string{"alice", "pw%4"} {
		if strings.Contains(f.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", f.Reason, leaked)
		}
	}

	// The legal https contract is untouched: credentials and their encoding
	// survive a save/re-read byte for byte and still resolve.
	legal := mustConfig(t, `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"https://alice:s3cr%40t@host.internal/v1"}]}`)
	savedLegal, err := json.Marshal(legal)
	if err != nil {
		t.Fatalf("marshal legal: %v", err)
	}
	if !strings.Contains(string(savedLegal), `"upstream":"https://alice:s3cr%40t@host.internal/v1"`) {
		t.Fatalf("legal credentials must survive the save: %s", savedLegal)
	}
	reparsed := mustConfig(t, string(savedLegal))
	res := resolveJSON(t, reparsed, `{"method":"GET","target":"/x"}`)
	if want := "https://alice:s3cr%40t@host.internal/v1/x"; res.UpstreamURL != want {
		t.Fatalf("reparsed upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

// TestSchemelessUpstreamQueryFragmentPrecedence pins the one check that
// still precedes address splitting: a "?" or "#" keeps its existing rule,
// and that reason never quotes the credential either.
func TestSchemelessUpstreamQueryFragmentPrecedence(t *testing.T) {
	f := assertSchemelessRejected(t, schemelessConfig("//alice:secret@h?q=1"), "",
		[]string{"alice", "secret"})
	if !strings.Contains(f.Reason, "must not contain a query string or fragment") {
		t.Fatalf("reason = %q, want the query/fragment rule", f.Reason)
	}
}

// TestRedactUpstreamUserinfoSchemelessDirectly pins the redaction helper on
// the schemeless boundary, including the no-userinfo and no-authority
// shapes that must stay untouched.
func TestRedactUpstreamUserinfoSchemelessDirectly(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"//alice:pw%4@api.internal/v1", "//***@api.internal/v1"},
		{"//alice@host/base", "//***@host/base"},
		{"//@host/base", "//***@host/base"},
		{"//host/base", "//host/base"},
		{"//host/base@x", "//host/base@x"},
		{"//", "//"},
		{"api.internal/v1", "api.internal/v1"},
		{"/abs/path", "/abs/path"},
		{"https://alice:pw@h/v1", "https://***@h/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := redactUpstreamUserinfo(tc.raw); got != tc.want {
				t.Fatalf("redactUpstreamUserinfo(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
