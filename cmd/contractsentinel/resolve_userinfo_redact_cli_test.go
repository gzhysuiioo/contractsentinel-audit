package main

import (
	"strings"
	"testing"
)

// TestResolveCLIUpstreamFailureRedactsUserinfo drives the credential-hiding
// rule through the resolve command: when a config is rejected because of an
// upstream address problem, the JSON error on stderr is the only diagnostic
// a user saves, so its reason must carry the address with "***@" standing in
// for the whole userinfo span — never the username, never the password
// (encoded or decoded) — while still stating the actual cause and locating
// route position, id and upstream field. Exit stays non-zero and stdout
// stays completely empty, as for every invalid_config failure.
func TestResolveCLIUpstreamFailureRedactsUserinfo(t *testing.T) {
	cases := []struct {
		name      string
		upstream  string
		wantQuote string
		cause     []string
		leaks     []string
	}{
		{
			name:      "headline encoded password before a bare port",
			upstream:  "https://user:p%40ss@:8443/v1",
			wantQuote: "https://***@:8443/v1",
			cause:     []string{"missing a host"},
			leaks:     []string{"p%40ss", "p@ss", "user:"},
		},
		{
			name:      "plain password before a bare port",
			upstream:  "http://alice:s3cret@:8080/base",
			wantQuote: "http://***@:8080/base",
			cause:     []string{"missing a host"},
			leaks:     []string{"alice", "s3cret"},
		},
		{
			name:      "username only before a bare port",
			upstream:  "https://alice@:8443/v1",
			wantQuote: "https://***@:8443/v1",
			cause:     []string{"missing a host"},
			leaks:     []string{"alice"},
		},
		{
			name:      "empty username still hides the span",
			upstream:  "https://@:8443/v1",
			wantQuote: "https://***@:8443/v1",
			cause:     []string{"missing a host"},
			leaks:     []string{`"https://@`},
		},
		{
			name:      "empty password hides the username with it",
			upstream:  "https://alice:@:8443/v1",
			wantQuote: "https://***@:8443/v1",
			cause:     []string{"missing a host"},
			leaks:     []string{"alice"},
		},
		{
			name:      "colon inside password before a bare port",
			upstream:  "http://:pa:ss@:8080/base",
			wantQuote: "http://***@:8080/base",
			cause:     []string{"missing a host"},
			leaks:     []string{"pa:ss"},
		},
		{
			name:      "userinfo before an extra-colon host",
			upstream:  "https://alice:pa:ss@api:internal:8080/base",
			wantQuote: "https://***@api:internal:8080/base",
			cause:     []string{"more than one colon"},
			leaks:     []string{"alice", "pa:ss"},
		},
		{
			name:      "several at signs hide one span up to the last one",
			upstream:  "http://a:b@c:d@host:part:80/base",
			wantQuote: "http://***@host:part:80/base",
			cause:     []string{"more than one colon"},
			leaks:     []string{"a:b", "c:d"},
		},
		{
			name:      "bad percent escape after userinfo",
			upstream:  "http://alice:p%40ss@h.internal/base%zz",
			wantQuote: `parse "http://***@h.internal/base%zz": invalid URL escape "%zz"`,
			cause:     []string{"upstream is not a valid URL"},
			leaks:     []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:      "bad percent escape inside the password",
			upstream:  "http://alice:p%zz@h.internal/base",
			wantQuote: `parse "http://***@h.internal/base": invalid URL escape "%zz"`,
			cause:     []string{"upstream is not a valid URL"},
			leaks:     []string{"alice", "p%zz@"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "broken", "methods": ["GET"], "pathPrefix": "/b", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			// The request only matches the valid first route; the bad second
			// route still rejects the whole config before stdin is read.
			res := runResolveCLI(t, config, cliSuccessRequest)

			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
			}
			var fail struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", fail.Code)
			}
			want := append([]string{"route 2", `"broken"`, "upstream", tc.wantQuote}, tc.cause...)
			for _, sub := range want {
				if !strings.Contains(fail.Reason, sub) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, sub)
				}
			}
			for _, leak := range tc.leaks {
				if strings.Contains(fail.Reason, leak) {
					t.Errorf("reason = %q leaked credential/raw token %q", fail.Reason, leak)
				}
			}
		})
	}
}

// TestResolveCLIRedactedAtSignOnlyInBasePath checks the boundary on the
// command: an '@' after the first path slash belongs to the base path, so
// a failing address whose only '@' sits there is shown verbatim (there is
// no userinfo to hide), while a successful route keeps the raw '@' in its
// upstreamURL.
func TestResolveCLIRedactedAtSignOnlyInBasePath(t *testing.T) {
	// Bad port-colon shape is caught by the unbracketed-host check; the '@'
	// in the base path must remain visible because it is not userinfo.
	config := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/r",
	  "upstream":"http://name:part:80/base@x"}]}`
	res := runResolveCLI(t, config, cliSuccessRequest)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", fail.Code)
	}
	if want := `"http://name:part:80/base@x"`; !strings.Contains(fail.Reason, want) {
		t.Fatalf("reason = %q, want the base-path '@' preserved in %q", fail.Reason, want)
	}
	if strings.Contains(fail.Reason, "***") {
		t.Fatalf("reason = %q must not redact an '@' that is only in the base path", fail.Reason)
	}
}
