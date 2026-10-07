package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRedactUpstream pins the hiding rule applied to every upstream address
// quoted in a failure reason: the whole userinfo span — username and an
// optional password — is replaced by the one token "***", the '@' that
// separates it from the host stays, and everything else is copied byte for
// byte. The span boundary is splitUpstream's: the authority after "://" up
// to the first path slash, split at its LAST '@', so an '@' in the base
// path is ordinary path text and several '@' signs hide as one span. The
// decision runs on raw bytes without percent-decoding, so an encoded
// password is never shown decoded; an empty username, an empty password, a
// password containing a colon or a username on its own hides the whole span
// too. Addresses without an '@' in the authority come back untouched, so
// diagnostics that previously showed no address gain none.
func TestRedactUpstream(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"headline encoded password before a bare port",
			"https://user:p%40ss@:8443/v1", "https://***@:8443/v1"},
		{"plain userinfo before a bare port",
			"http://user:pass@:8080/base", "http://***@:8080/base"},
		{"username only is hidden entirely",
			"https://alice@:8443/v1", "https://***@:8443/v1"},
		{"empty username still hides the span",
			"https://@:8443/v1", "https://***@:8443/v1"},
		{"empty password hides username and separator together",
			"https://alice:@:8443/v1", "https://***@:8443/v1"},
		{"empty username with a colon-bearing password",
			"http://:pa:ss@:8080/base", "http://***@:8080/base"},
		{"colon inside the password is part of the hidden span",
			"http://alice:b:c@:8080/base", "http://***@:8080/base"},
		{"several at signs hide everything before the last one",
			"http://a:b@c:d@host:part:80/b", "http://***@host:part:80/b"},
		{"two at signs without a password hide as one span",
			"http://alice@bob@host/base", "http://***@host/base"},
		{"an at sign in the base path is not userinfo",
			"http://host/base@x?z=1", "http://host/base@x?z=1"},
		{"ordinary address without userinfo is copied verbatim",
			"http://host:8080/base", "http://host:8080/base"},
		{"hostless address without userinfo is copied verbatim",
			"http://:8080/base", "http://:8080/base"},
		{"userinfo with a host is hidden up to the at sign",
			"http://alice:secret@host:8080/b", "http://***@host:8080/b"},
		{"text without a scheme is left untouched",
			"not a url at all", "not a url at all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactUpstream(tc.raw); got != tc.want {
				t.Fatalf("redactUpstream(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}

	// No spelling of credentials may survive hiding: the encoded password is
	// never percent-decoded for display, and the username is hidden whether
	// or not a password follows.
	hidden := redactUpstream("https://user:p%40ss@:8443/v1")
	for _, leak := range []string{"p%40ss", "p@ss", "user:"} {
		if strings.Contains(hidden, leak) {
			t.Fatalf("redactUpstream leaked %q in %q", leak, hidden)
		}
	}
}

// TestParseConfigUpstreamFailureRedactsUserinfo drives the hiding rule
// through the public config reader for each address-content failure that
// quotes the upstream: the missing-host check, the unbracketed extra-colon
// check and url.Parse's own failures (bad escape, bad port, missing
// bracket). Every reason must show the address with "***@" in place of the
// userinfo, must never show the configured username or password (encoded or
// decoded), and must not quote url.Parse's parse "<full URL>" wrapper. The
// reason still states the actual cause with the route's 1-based position,
// its valid non-empty id and the upstream field, the code stays
// invalid_config, and no config is returned.
func TestParseConfigUpstreamFailureRedactsUserinfo(t *testing.T) {
	cases := []struct {
		name      string
		upstream  string
		wantQuote string // the redacted address (or host part) quoted in the reason
		// cause must each appear in the reason; leaks must each be absent.
		cause []string
		leaks []string
	}{
		{
			name:      "headline encoded password before a missing host",
			upstream:  "https://user:p%40ss@:8443/v1",
			wantQuote: `"https://***@:8443/v1"`,
			cause:     []string{"missing a host"},
			leaks:     []string{"p%40ss", "p@ss", "user:"},
		},
		{
			name:      "plain password before a missing host",
			upstream:  "http://alice:s3cret@:8080/base",
			wantQuote: `"http://***@:8080/base"`,
			cause:     []string{"missing a host"},
			leaks:     []string{"alice", "s3cret"},
		},
		{
			name:      "username only before a missing host",
			upstream:  "https://alice@:8443/v1",
			wantQuote: `"https://***@:8443/v1"`,
			cause:     []string{"missing a host"},
			leaks:     []string{"alice"},
		},
		{
			name:      "empty username before a missing host",
			upstream:  "https://@:8443/v1",
			wantQuote: `"https://***@:8443/v1"`,
			cause:     []string{"missing a host"},
		},
		{
			name:      "empty password before a missing host",
			upstream:  "https://alice:@:8443/v1",
			wantQuote: `"https://***@:8443/v1"`,
			cause:     []string{"missing a host"},
			leaks:     []string{"alice@"},
		},
		{
			name:      "colon-bearing password with an empty username before a missing host",
			upstream:  "http://:pa:ss@:8080/base",
			wantQuote: `"http://***@:8080/base"`,
			cause:     []string{"missing a host"},
			leaks:     []string{"pa:ss"},
		},
		{
			name:      "userinfo before an extra-colon host",
			upstream:  "https://alice:pa:ss@api:internal:8080/base",
			wantQuote: `"https://***@api:internal:8080/base"`,
			cause:     []string{"more than one colon", `"api:internal:8080"`},
			leaks:     []string{"alice", "pa:ss"},
		},
		{
			name:      "multiple at signs before an extra-colon host",
			upstream:  "http://a:b@c:d@host:part:80/base",
			wantQuote: `"http://***@host:part:80/base"`,
			cause:     []string{"more than one colon", `"host:part:80"`},
			leaks:     []string{"a:b", "c:d"},
		},
		{
			name:      "bad escape in the base path after userinfo",
			upstream:  "http://alice:p%40ss@h.internal/base%zz",
			wantQuote: `parse "http://***@h.internal/base%zz": invalid URL escape "%zz"`,
			cause:     []string{"upstream is not a valid URL"},
			leaks:     []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:      "bad escape inside the password",
			upstream:  "http://alice:p%zz@h.internal/base",
			wantQuote: `parse "http://***@h.internal/base": invalid URL escape "%zz"`,
			cause:     []string{"upstream is not a valid URL"},
			leaks:     []string{"alice", "p%zz@"},
		},
		{
			name:      "bad escape in a username without a password",
			upstream:  "http://%zz@h.internal/base",
			wantQuote: `parse "http://***@h.internal/base": invalid URL escape "%zz"`,
			cause:     []string{"upstream is not a valid URL"},
			// The detail may name the bad token "%zz", but the full span
			// "%zz@host" from the quoted URL must not come back.
			leaks: []string{"%zz@"},
		},
		{
			name:      "missing closing bracket after userinfo",
			upstream:  "http://alice:secret@[::1/base",
			wantQuote: "closing ']' is missing",
			cause:     []string{"bracketed host"},
			leaks:     []string{"alice", "secret", `parse "`},
		},
		{
			name:      "non numeric port after userinfo",
			upstream:  "http://alice:secret@host:80ab/base",
			wantQuote: `parse "http://***@host:80ab/base": invalid port ":80ab" after host`,
			cause:     []string{"upstream is not a valid URL"},
			leaks:     []string{"alice", "secret"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[
			  {"id":"first","methods":["GET"],"pathPrefix":"/f","upstream":"http://ok.internal/v1"},
			  {"id":"broken","methods":["GET"],"pathPrefix":"/b","upstream":"` + tc.upstream + `"}
			]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("expected invalid_config for upstream %q", tc.upstream)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
			want := append([]string{"route 2", `"broken"`, "upstream", tc.wantQuote}, tc.cause...)
			for _, sub := range want {
				if !strings.Contains(f.Reason, sub) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, sub)
				}
			}
			for _, leak := range tc.leaks {
				if strings.Contains(f.Reason, leak) {
					t.Fatalf("reason = %q leaked credential/raw address token %q", f.Reason, leak)
				}
			}
		})
	}
}

// TestParseConfigUpstreamFailureWithoutUserinfoUnchanged guards the other
// half of the rule: an address that carried no userinfo keeps its existing
// diagnostic wording byte for byte — including url.Parse's quoted address
// wrapper and the redaction marker never appearing.
func TestParseConfigUpstreamFailureWithoutUserinfoUnchanged(t *testing.T) {
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/r","upstream":"http://h.internal/base%zz"}]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	for _, want := range []string{
		"route 1", `"r"`, "upstream",
		`parse "http://h.internal/base%zz": invalid URL escape "%zz"`,
	} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want the existing wording substring %q", f.Reason, want)
		}
	}
	if strings.Contains(f.Reason, "***") {
		t.Fatalf("reason = %q must not gain a redaction marker without userinfo", f.Reason)
	}

	// An error that never showed an address does not gain one.
	src = `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/r","upstream":""}]}`
	if _, f := ParseConfig([]byte(src)); f == nil || !strings.Contains(f.Reason, "absolute http or https URL") {
		t.Fatalf("empty upstream: got %+v, want the existing absolute-URL reason", f)
	}
}

// TestValidUserinfoUpstreamStillAcceptedAndSaved confirms the change is
// confined to failure diagnostics: a legal upstream with userinfo is still
// accepted, the joined upstreamURL keeps the raw address including its
// percent encoding, and saving the config and re-reading it preserves the
// credentials byte for byte. Nothing is redacted on the success path.
func TestValidUserinfoUpstreamStillAcceptedAndSaved(t *testing.T) {
	rawUpstream := "https://user:p%40ss@[2001:db8::1]:8443/v%2f"
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/api","upstream":"` + rawUpstream + `"}]}`
	cfg := mustConfig(t, src)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/items?z=1"}`)
	if res.RouteID != "r" {
		t.Fatalf("routeId = %q, want r", res.RouteID)
	}
	if want := rawUpstream + "/items?z=1"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q (credentials must survive verbatim)", res.UpstreamURL, want)
	}

	saved, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if !strings.Contains(string(saved), rawUpstream) {
		t.Fatalf("saved config = %s, want raw upstream %q preserved", saved, rawUpstream)
	}
	reloaded := mustConfig(t, string(saved))
	res2 := resolveJSON(t, reloaded, `{"method":"GET","target":"/api/items?z=1"}`)
	if res2.UpstreamURL != res.UpstreamURL {
		t.Fatalf("after save upstreamURL = %q, want %q", res2.UpstreamURL, res.UpstreamURL)
	}
}
