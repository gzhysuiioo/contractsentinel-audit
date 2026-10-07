package main

import (
	"strings"
	"testing"
)

// These tests pin the fix at the command boundary for a credential that is
// itself an illegal percent escape, e.g.
// https://alice:%zz@host.internal/base: resolve must reject the config with
// the usual failure contract (non-zero exit, completely empty stdout and one
// JSON error on stderr with code invalid_config), the reason must locate the
// offending route by 1-based position, id and the upstream field and show
// the address with the whole userinfo replaced by "***", and neither the
// address nor any other part of the reason may repeat the malformed
// credential fragment. A bad escape that belongs to the host or base path
// keeps its specific diagnostic instead, with only the credentials hidden.

// TestResolveCLIBadUserinfoEscapeRejectsConfig drives the headline case on
// the second route, which the request never hits: the whole config is still
// rejected up front.
func TestResolveCLIBadUserinfoEscapeRejectsConfig(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "https://alice:%zz@host.internal/base"}
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
	for _, want := range []string{
		"route 2",
		`"admin"`,
		"upstream",
		"invalid percent escape in its userinfo",
		`"https://***@host.internal/base"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "%zz", `"%zz"`} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential fragment %q", fail.Reason, leaked)
		}
	}
}

// TestResolveCLIBadUserinfoEscapeVariants covers the first route and the
// truncated/lone escape shapes, including a bad username, so the CLI output
// is proven credential-free for every malformed shape.
func TestResolveCLIBadUserinfoEscapeVariants(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{"truncated password escape", "https://alice:pw%2@host.internal/base", "https://***@host.internal/base", []string{"alice", "pw%2", `"%2"`}},
		{"lone percent password", "http://alice:pw%@host/base", "http://***@host/base", []string{"alice", "pw%", `"%"`}},
		{"bad username with password", "https://%zz:secret@host.internal/base", "https://***@host.internal/base", []string{"secret", "%zz", `"%zz"`}},
		{"username only", "http://al%zz@host/base", "http://***@host/base", []string{"al%zz", `"%zz"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
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
			for _, want := range []string{"route 1", `"api"`, "upstream", "invalid percent escape in its userinfo", `"` + tc.shown + `"`} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks %q", fail.Reason, leaked)
				}
			}
		})
	}
}

// TestResolveCLIBadHostEscapeWithCredentialsKeepsHostDiagnostic pins the
// redaction boundary at the command boundary: a legal userinfo plus a bad
// host escape keeps the existing host-specific reason and its fragment,
// hiding only the credentials.
func TestResolveCLIBadHostEscapeWithCredentialsKeepsHostDiagnostic(t *testing.T) {
	config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"https://alice:secret@ho%zzst/"}]}`
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
		"route 1",
		`"api"`,
		"upstream",
		"not a valid URL",
		`parse "https://***@ho%zzst/"`,
		`invalid URL escape "%zz"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "secret"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
		}
	}
}
