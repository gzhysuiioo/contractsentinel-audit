package main

import (
	"strings"
	"testing"
)

// These tests pin the upstream userinfo redaction at the command boundary:
// when a config error reason quotes an upstream address that carries
// credentials, the resolve command's stderr JSON shows the address with the
// whole userinfo segment replaced by "***" (the '@' kept), so saving the
// diagnostic cannot persist the password. The run still exits non-zero with
// completely empty stdout and the invalid_config code, and a legal upstream
// with userinfo still resolves with the original address in upstreamURL.

// TestResolveCLIUpstreamUserinfoRedactedOnFailure drives the failure
// contract: an upstream whose credentials precede a missing host is
// rejected, and the stderr reason shows "https://***@:8443/v1" — never the
// username, never the password, encoded or decoded — while still naming the
// route position, its id, the upstream field and the actual problem.
func TestResolveCLIUpstreamUserinfoRedactedOnFailure(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "https://alice:s3cr%40t@:8443/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
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
	for _, want := range []string{"route 2", `"admin"`, "upstream", "missing a host", `"https://***@:8443/v1"`} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "s3cr%40t", "s3cr@t"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks userinfo %q", fail.Reason, leaked)
		}
	}
}

// TestResolveCLIUpstreamUserinfoPreservedOnSuccess drives the success
// contract: redaction only touches failure diagnostics, so a legal upstream
// with userinfo resolves with the original address — credentials and
// percent escapes included — in upstreamURL.
func TestResolveCLIUpstreamUserinfoPreservedOnSuccess(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "https://alice:s3cr%40t@host.internal:8443/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
	hit := assertResolveSuccess(t, res)
	if hit.RouteID != "api" {
		t.Errorf("routeId = %q, want api", hit.RouteID)
	}
	if want := "https://alice:s3cr%40t@host.internal:8443/v1/items"; hit.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", hit.UpstreamURL, want)
	}
}

// TestResolveCLIUserinfoInvalidEscapeRedacted drives the credential-leak
// fix at the command boundary: a password that is itself an illegal percent
// escape ("https://alice:%zz@host.internal/base") rejects the whole config
// even though the request only hits the valid first route. The stderr JSON
// keeps the resolve failure contract — code invalid_config, non-zero exit,
// completely empty stdout — and its reason locates route 2, its id and the
// upstream field, explains the userinfo percent escape, and shows the
// address masked as "https://***@host.internal/base" without the username,
// the password or the offending "%zz" fragment appearing anywhere.
func TestResolveCLIUserinfoInvalidEscapeRedacted(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{
			name:     "password is an illegal escape",
			upstream: "https://alice:%zz@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice", "%zz"},
		},
		{
			name:     "truncated escape at the end of the password",
			upstream: "https://alice:p%4@host.internal/base",
			shown:    "https://***@host.internal/base",
			hidden:   []string{"alice", "p%4"},
		},
		{
			name:     "illegal escape in the username",
			upstream: "http://a%zzb@host.internal/base",
			shown:    "http://***@host.internal/base",
			hidden:   []string{"a%zzb", "%zz"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
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
			for _, want := range []string{
				"route 2",
				`"admin"`,
				"upstream",
				"userinfo",
				"percent",
				`"` + tc.shown + `"`,
			} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential fragment %q", fail.Reason, leaked)
				}
			}
			if strings.Contains(fail.Reason, "invalid URL escape") {
				t.Fatalf("reason must not quote url.Parse's escape text: %q", fail.Reason)
			}
		})
	}
}

// TestResolveCLINonUserinfoEscapeStaysSpecific pins the masking boundary at
// the command boundary: an illegal escape in the host or base path keeps
// url.Parse's verbatim escape text, and an '@' in the base path is never
// treated as a userinfo separator.
func TestResolveCLINonUserinfoEscapeStaysSpecific(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		want     []string
		hidden   []string
	}{
		{
			name:     "host escape with legal userinfo",
			upstream: "https://alice:secret@ho%zzst/",
			want:     []string{"route 2", `"admin"`, "upstream", `parse "https://***@ho%zzst/"`, `invalid URL escape "%zz"`, "ho%zzst"},
			hidden:   []string{"alice", "secret"},
		},
		{
			name:     "base path escape with an at sign but no userinfo",
			upstream: "http://host.internal/v1@x/b%zz",
			want:     []string{"route 2", `"admin"`, "upstream", `parse "http://host.internal/v1@x/b%zz"`, `invalid URL escape "%zz"`, "v1@x"},
			hidden:   []string{"***"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
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
			for _, want := range tc.want {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks or wrongly masks %q", fail.Reason, leaked)
				}
			}
		})
	}
}
