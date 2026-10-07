package main

import (
	"strings"
	"testing"
)

// These tests pin at the command boundary the credential-redaction fix for
// a schemeless upstream — an address written with a leading "//" and no
// scheme, e.g. //alice:pw%4@api.internal/v1. Such an upstream is always
// rejected (resolve never adds http or https on the user's behalf), but the
// failure contract is the same as for a scheme-bearing address: non-zero
// exit, completely empty stdout and one JSON error on stderr with code
// invalid_config, the reason locates the offending route by its 1-based
// position, id and the upstream field, the address may only appear as
// "//***@host/..." and neither the original nor the decoded credential may
// appear anywhere. A bad escape in the base path keeps the path-escape
// diagnostic while only the credentials are hidden.

// TestResolveCLISchemelessBadUserinfoEscapeRejectsConfig drives the
// headline case on the second route, which the request never hits: the
// whole config is rejected up front and the credential never reaches
// stdout, stderr in raw form, or any decoded form.
func TestResolveCLISchemelessBadUserinfoEscapeRejectsConfig(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "//alice:pw%4@api.internal/v1"}
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
		`"//***@api.internal/v1"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", "p@", `"%4"`, "//alice", "https://", "http://"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", fail.Reason, leaked)
		}
	}
	if strings.Contains(fail.Reason, "not valid JSON") {
		t.Fatalf("a schemeless upstream is a content error, not a JSON syntax failure: %q", fail.Reason)
	}
}

// TestResolveCLISchemelessBadUserinfoEscapeVariants covers the malformed
// credential shapes on a first route, proving the command output is
// credential-free for each while the redacted address keeps "//".
func TestResolveCLISchemelessBadUserinfoEscapeVariants(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
		hidden   []string
	}{
		{"truncated password escape", "//alice:pw%2@host.internal/base", "//***@host.internal/base", []string{"alice", "pw%2", `"%2"`}},
		{"lone percent password", "//alice:pw%@host/base", "//***@host/base", []string{"alice", "pw%", `"%"`}},
		{"bad username with password", "//%zz:secret@host.internal/base", "//***@host.internal/base", []string{"secret", "%zz", `"%zz"`}},
		{"username only", "//al%zz@host/base", "//***@host/base", []string{"al%zz", `"%zz"`}},
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

// TestResolveCLISchemelessLegalUserinfoStillRejectedSilently pins that a
// schemeless address with legal credentials is rejected for the missing
// scheme and its reason never quotes the address (so the credentials stay
// hidden) and never gains an http/https prefix.
func TestResolveCLISchemelessLegalUserinfoStillRejectedSilently(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		hidden   []string
	}{
		{"encoded password", "//alice:p%40ss@api.internal/v1", []string{"alice", "p%40ss", "p@ss"}},
		{"plain userinfo", "//alice:secret@host.internal/base", []string{"alice", "secret"}},
		{"username only", "//alice@host/base", []string{"alice"}},
		{"no userinfo", "//api.internal/v1", nil},
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
			for _, want := range []string{"route 1", `"api"`, "upstream", "upstream must be an absolute http or https URL"} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
				}
			}
			for _, scheme := range []string{"http://", "https://"} {
				if strings.Contains(fail.Reason, scheme) {
					t.Fatalf("reason = %q must not add a scheme", fail.Reason)
				}
			}
		})
	}
}

// TestResolveCLISchemelessPathEscapeKeepsPathDiagnostic pins the redaction
// boundary at the command boundary: a legal userinfo plus a bad base-path
// escape keeps the path-escape diagnostic and its fragment (including an
// '@' that is merely path content), hiding only the credentials.
func TestResolveCLISchemelessPathEscapeKeepsPathDiagnostic(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		shown    string
	}{
		{"bad base path escape", "//alice:p%40ss@api.internal/%zz", "//***@api.internal/%zz"},
		{"at sign in base path stays path content", "//alice:pw9@host.internal/v1@x%zz", "//***@host.internal/v1@x%zz"},
		{"bad host escape", "//alice:secret@ho%zzst/", "//***@ho%zzst/"},
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
			for _, want := range []string{
				"route 1",
				`"api"`,
				"upstream",
				"not a valid URL",
				`parse "` + tc.shown + `"`,
				`invalid URL escape "%zz"`,
			} {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, leaked := range []string{"alice", "p%40ss", "pw9", "secret"} {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
				}
			}
			if strings.Contains(fail.Reason, "invalid percent escape in its userinfo") {
				t.Fatalf("a host/path escape must not be mislabeled a userinfo error: %q", fail.Reason)
			}
		})
	}
}

// TestResolveCLISchemelessSchemeTextInBasePath drives the credential-leak
// fix at the command boundary when the schemeless upstream's base path
// itself contains "http://"/"https://" text: that text must not be read as
// the address's scheme marker. A malformed credential escape yields the
// userinfo reason with the address shown only as
// "//***@host/...scheme text..."; a legal credential plus a bad base-path
// escape keeps the path-escape diagnostic and its fragment; and a fully
// legal address is still rejected for the missing scheme. In every shape
// stdout is empty, the exit is non-zero and one JSON invalid_config error
// names the route.
func TestResolveCLISchemelessSchemeTextInBasePath(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		want     []string
		shown    string
		hidden   []string
	}{
		{
			name:     "bad credential escape with http text in base path",
			upstream: "//alice:pw%4@api.internal/http://mirror/v1",
			want:     []string{"invalid percent escape in its userinfo"},
			shown:    "//***@api.internal/http://mirror/v1",
			hidden:   []string{"alice", "pw%4", "%4", `"%4"`, "//alice"},
		},
		{
			name:     "legal credentials, bad base path escape after https text",
			upstream: "//alice:p%40ss@api.internal/https://mirror/%zz",
			want:     []string{"not a valid URL", `invalid URL escape "%zz"`},
			shown:    "//***@api.internal/https://mirror/%zz",
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
		{
			name:     "at sign in that base path stays path content",
			upstream: "//alice:pw9@host.internal/https://mirror/%zz@x",
			want:     []string{"not a valid URL", `invalid URL escape "%zz"`, "/https://mirror/%zz@x"},
			shown:    "//***@host.internal/https://mirror/%zz@x",
			hidden:   []string{"alice", "pw9"},
		},
		{
			name:     "everything legal still rejected for the missing scheme",
			upstream: "//alice:p%40ss@api.internal/http://mirror/v1",
			want:     []string{"upstream must be an absolute http or https URL"},
			shown:    "",
			hidden:   []string{"alice", "p%40ss", "p@ss"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"reader","methods":["GET"],"pathPrefix":"/r","upstream":"` + tc.upstream + `"}]}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/r/items"}`)
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
			for _, want := range append([]string{"route 1", `"reader"`, "upstream"}, tc.want...) {
				if !strings.Contains(fail.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			if tc.shown != "" && !strings.Contains(fail.Reason, `"`+tc.shown+`"`) {
				t.Fatalf("reason = %q, want the redacted address %q quoted", fail.Reason, tc.shown)
			}
			for _, leaked := range tc.hidden {
				if strings.Contains(fail.Reason, leaked) {
					t.Fatalf("reason = %q leaks credential %q", fail.Reason, leaked)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Fatalf("a schemeless upstream is a content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}
}

// TestResolveCLISchemelessSchemeTextRejectsUnhitRoute pins the
// read-the-whole-config contract end to end: the only request hits route 1,
// but route 2's schemeless upstream with inner scheme text and a bad
// credential escape fails the read before stdin is consumed, leaving stdout
// empty and emitting one redacted invalid_config error.
func TestResolveCLISchemelessSchemeTextRejectsUnhitRoute(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "reader", "methods": ["GET"], "pathPrefix": "/reader", "upstream": "//alice:pw%4@api.internal/http://mirror/v1"}
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
		`"reader"`,
		"upstream",
		"invalid percent escape in its userinfo",
		`"//***@api.internal/http://mirror/v1"`,
	} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4", "%4", `"%4"`, "//alice"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", fail.Reason, leaked)
		}
	}
}

// TestResolveCLISchemelessConfigWinsOverInvalidRequest pins that a
// schemeless upstream on the only route is validated before the request is
// even read: a broken request still yields invalid_config with empty
// stdout, and the credential stays hidden.
func TestResolveCLISchemelessConfigWinsOverInvalidRequest(t *testing.T) {
	config := `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/x","upstream":"//alice:pw%4@host.internal/v1"}]}`
	res := runResolveCLI(t, config, `{not json`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config to take priority", fail.Code)
	}
	for _, want := range []string{"route 1", `"x"`, "upstream", `"//***@host.internal/v1"`} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "pw%4"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks %q", fail.Reason, leaked)
		}
	}
}
