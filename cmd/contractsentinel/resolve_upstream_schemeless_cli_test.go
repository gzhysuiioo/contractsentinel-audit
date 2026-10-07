package main

import (
	"strings"
	"testing"
)

// These tests pin the credential-hiding fix at the resolve command
// boundary for an upstream written as a schemeless protocol-relative
// reference ("//user:pass@host/path"): such an upstream is always rejected
// — the command never completes it to http or https — and the failure
// keeps the same contract every invalid_config failure has: non-zero exit,
// completely empty stdout and exactly one JSON error on stderr carrying
// code invalid_config and a reason that locates the route by its 1-based
// position, its non-empty id and the upstream field. The address may only
// appear as "//***@host/path"; the raw or decoded credentials must never
// appear anywhere, while a malformed escape that belongs to the host or
// base path keeps its own diagnostic. One bad route rejects the whole
// config even when the request only hits another, legal route.

// assertResolveInvalidConfig is the shared failure contract: non-zero exit,
// empty stdout, one JSON {code,reason} on stderr with code invalid_config.
func assertResolveInvalidConfig(t *testing.T, res resolveResult) struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
} {
	t.Helper()
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
	return fail
}

// TestResolveCLISchemelessHeadline drives the headline case from the bug
// report on the route the request never hits: the whole config is rejected
// up front and the reason may show the address only as
// "//***@api.internal/v1".
func TestResolveCLISchemelessHeadline(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "//alice:pw%4@api.internal/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
	fail := assertResolveInvalidConfig(t, res)

	for _, want := range []string{
		"route 2",
		`"admin"`,
		"upstream",
		`"//***@api.internal/v1"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", "pwa", `"%4"`} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
		}
	}
	if strings.Contains(fail.Reason, "not valid JSON") {
		t.Fatalf("a schemeless upstream is a content error in legal JSON: %q", fail.Reason)
	}
}

// TestResolveCLISchemelessUserinfoEscapeVariants covers every malformed
// userinfo shape on the first route, so the command output is proven
// credential-free for each: the bad fragment stays in the username or
// password and the fixed reason points at the userinfo without quoting it.
func TestResolveCLISchemelessUserinfoEscapeVariants(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{"illegal password escape", "//alice:%zz@host.internal/base", "//***@host.internal/base", []string{"alice", "%zz", `"%zz"`}},
		{"truncated password escape", "//alice:pw%2@host.internal/base", "//***@host.internal/base", []string{"alice", "pw%2", `"%2"`}},
		{"mid password truncated escape", "//alice:p%4@host.internal/", "//***@host.internal/", []string{"alice", "p%4", `"%4"`}},
		{"lone percent password", "//alice:pw%@host/", "//***@host/", []string{"alice", "pw%", `"%"`}},
		{"bad username with password", "//%zz:secret@host.internal/base", "//***@host.internal/base", []string{"secret", "%zz", `"%zz"`}},
		{"username only bad escape", "//al%zz@host/base", "//***@host/base", []string{"al%zz", `"%zz"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
			fail := assertResolveInvalidConfig(t, res)
			for _, want := range []string{"route 1", `"api"`, "upstream", "userinfo", `"` + tc.shown + `"`} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential fragment %q", fail.Reason, leaked)
				}
			}
		})
	}
}

// TestResolveCLISchemelessPathEscapeKeepsPathDiagnostic pins the boundary
// at the command: legal credentials plus a bad base-path escape hides only
// the credentials and keeps the path's "%zz" (and a path '@'), even for a
// schemeless upstream.
func TestResolveCLISchemelessPathEscapeKeepsPathDiagnostic(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{
			name:     "bad path escape with legal credentials",
			upstream: "//alice:p%40ss@api.internal/%zz",
			shown:    "//***@api.internal/%zz",
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "at sign in the base path is path text",
			upstream: "//alice:pw9@host.internal/v1@x%zz",
			shown:    "//***@host.internal/v1@x%zz",
			hidden:   []string{"alice", "pw9"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"` + tc.upstream + `"}]}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
			fail := assertResolveInvalidConfig(t, res)
			for _, want := range []string{
				"route 1", `"api"`, "upstream",
				"not a valid URL",
				`parse "` + tc.shown + `"`,
				`invalid URL escape "%zz"`,
			} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
				}
			}
		})
	}
}

// TestResolveCLISchemelessHostErrorKeepsHostDiagnostic pins that a host
// problem with credentials on a schemeless upstream keeps the host wording
// and host bytes; only the credentials are hidden.
func TestResolveCLISchemelessHostErrorKeepsHostDiagnostic(t *testing.T) {
	config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"//alice:secret@ho%zzst/"}]}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
	fail := assertResolveInvalidConfig(t, res)
	for _, want := range []string{
		"route 1", `"api"`, "upstream",
		"not a valid URL",
		`parse "//***@ho%zzst/"`,
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

// TestResolveCLISchemelessCleanAddressStillRejected pins that an otherwise
// well-formed schemeless upstream with legal credentials is rejected
// without a scheme ever being added; the credentials must not leak even
// though this particular reason does not quote the address.
func TestResolveCLISchemelessCleanAddressStillRejected(t *testing.T) {
	config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"//alice:s3cr%40t@api.internal:8443/v1"}]}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
	fail := assertResolveInvalidConfig(t, res)
	for _, want := range []string{"route 1", `"api"`, "upstream", "absolute http or https URL"} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "s3cr%40t", "s3cr@t"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
		}
	}
	for _, completed := range []string{"http://alice", "https://alice"} {
		if strings.Contains(fail.Reason, completed) {
			t.Fatalf("the schemeless upstream must never be completed: %q", fail.Reason)
		}
	}
}

// TestResolveCLISchemelessBadConfigBeatsBadRequest pins read ordering at
// the boundary: the invalid schemeless config is rejected before stdin is
// examined, so even broken request JSON yields invalid_config, stdout
// stays empty and the exit status is non-zero.
func TestResolveCLISchemelessBadConfigBeatsBadRequest(t *testing.T) {
	config := `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/x","upstream":"//alice:pw%4@host/v1"}]}`
	res := runResolveCLI(t, config, `{not json`)
	fail := assertResolveInvalidConfig(t, res)
	for _, want := range []string{"route 1", `"x"`, "upstream", `//***@host/v1`} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
		}
	}
}
