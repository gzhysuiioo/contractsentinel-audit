package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// These tests pin conflict adjudication at the command boundary after a
// save: the config is parsed through the public entry point, written with
// the standard library's encoding/json (the supported save path) and read
// back, and the real `resolve` command is then run offline against both the
// original and the saved config files. Exit status, stdout and stderr must
// match byte for byte in their observable JSON content, so a save cannot
// turn a conflict into a success, change the error code or move candidates.

// saveConfigJSON parses a config document through the public reader and
// writes it back with encoding/json, failing the test if the saved document
// would not re-read as a legal config.
func saveConfigJSON(t *testing.T, src string) string {
	t.Helper()
	cfg, f := contractsentinel.ParseConfig([]byte(src))
	if f != nil {
		t.Fatalf("parse original config: %v", f)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if _, f := contractsentinel.ParseConfig(out); f != nil {
		t.Fatalf("saved config rejected on re-read: %v\n%s", f, out)
	}
	return string(out)
}

// assertCLISameResult runs resolve against the original and the saved
// config and requires identical observable behavior: exit status, the full
// stdout (routeId/upstreamURL on success) and the full stderr JSON
// (code/reason/candidates on failure).
func assertCLISameResult(t *testing.T, original, saved, request string) resolveResult {
	t.Helper()
	before := runResolveCLI(t, original, request)
	after := runResolveCLI(t, saved, request)
	if before.exitCode != after.exitCode {
		t.Fatalf("exit status changed across save for %s: %d vs %d\n before stderr: %s\n after stderr:  %s",
			request, before.exitCode, after.exitCode, before.stderr, after.stderr)
	}
	if string(before.stdout) != string(after.stdout) {
		t.Fatalf("stdout changed across save for %s:\n before: %s\n after:  %s",
			request, before.stdout, after.stdout)
	}
	if string(before.stderr) != string(after.stderr) {
		t.Fatalf("stderr changed across save for %s:\n before: %s\n after:  %s",
			request, before.stderr, after.stderr)
	}
	return after
}

// cliFailure is the stderr failure contract decoded for explicit assertions.
type cliFailure struct {
	Code       string   `json:"code"`
	Reason     string   `json:"reason"`
	Candidates []string `json:"candidates"`
}

func decodeCLIFailure(t *testing.T, res resolveResult) cliFailure {
	t.Helper()
	if res.exitCode == 0 {
		t.Fatalf("expected non-zero exit, got success: %s", res.stdout)
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want empty on failure", res.stdout)
	}
	var f cliFailure
	decodeOneJSON(t, res.stderr, "stderr", &f)
	return f
}

func TestResolveCLISaveKeepsLongestWildcardWin(t *testing.T) {
	// Two concrete GET routes share /a; a wildcard route owns the longer
	// /a/b. Before and after saving, a request inside /a/b selects the
	// wildcard with the stripped path and the raw query intact, while a
	// request under /a alone stays a conflict.
	config := `{
	  "routes": [
	    {"id": "short-one", "methods": ["GET"], "pathPrefix": "/a", "upstream": "http://one.internal/s1"},
	    {"id": "short-two", "methods": ["GET"], "pathPrefix": "/a", "upstream": "http://two.internal/s2"},
	    {"id": "long-wild", "methods": ["*"], "pathPrefix": "/a/b", "upstream": "http://wild.internal/base"}
	  ]
	}`
	saved := saveConfigJSON(t, config)

	for _, req := range []string{
		`{"method":"GET","target":"/a/b/c/items?dup=1&dup=2&empty=&raw=%2f%41&%26=x"}`,
		`{"method":"GET","target":"/a/b"}`,
		`{"method":"POST","target":"/a/b/c"}`,
	} {
		res := assertCLISameResult(t, config, saved, req)
		if res.exitCode != 0 || len(res.stderr) != 0 {
			t.Fatalf("request %s: expected success, got exit %d stderr %s", req, res.exitCode, res.stderr)
		}
		var success struct {
			RouteID     string `json:"routeId"`
			UpstreamURL string `json:"upstreamURL"`
		}
		decodeOneJSON(t, res.stdout, "stdout", &success)
		if success.RouteID != "long-wild" {
			t.Fatalf("request %s: routeId = %q, want long-wild", req, success.RouteID)
		}
	}

	// Explicitly pin the full upstream for the deep path: remainder joined
	// after the stripped prefix, raw query with duplicates, empty value and
	// percent escapes kept byte for byte.
	res := runResolveCLI(t, saved,
		`{"method":"GET","target":"/a/b/c/items?dup=1&dup=2&empty=&raw=%2f%41&%26=x"}`)
	if res.exitCode != 0 {
		t.Fatalf("saved config: exit %d, stderr %s", res.exitCode, res.stderr)
	}
	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, res.stdout, "stdout", &success)
	wantURL := "http://wild.internal/base/c/items?dup=1&dup=2&empty=&raw=%2f%41&%26=x"
	if success.RouteID != "long-wild" || success.UpstreamURL != wantURL {
		t.Fatalf("saved config: got %+v, want long-wild / %q", success, wantURL)
	}

	// The short-prefix request stays a request-stage conflict after saving:
	// same code, non-empty reason and exactly the two short routes.
	res = assertCLISameResult(t, config, saved, `{"method":"GET","target":"/a/only?z=1"}`)
	f := decodeCLIFailure(t, res)
	if f.Code != "route_conflict" {
		t.Fatalf("code = %q, want route_conflict", f.Code)
	}
	if f.Reason == "" {
		t.Fatal("route_conflict must carry a reason")
	}
	if got := strings.Join(f.Candidates, ","); got != "short-one,short-two" {
		t.Fatalf("candidates = %v, want [short-one short-two]", f.Candidates)
	}
}

func TestResolveCLISaveKeepsConflictCandidatesExact(t *testing.T) {
	// At /a/b: two concrete GET routes (declared zeta before alpha, not in
	// lexicographic order), a same-prefix wildcard and a shorter concrete
	// route. The saved config must keep the GET conflict with only the two
	// concrete routes sorted; POST must still win the wildcard.
	config := `{
	  "routes": [
	    {"id": "z-short",   "methods": ["GET"], "pathPrefix": "/a",   "upstream": "http://short.internal"},
	    {"id": "wild-long", "methods": ["*"],   "pathPrefix": "/a/b", "upstream": "http://wild.internal/w"},
	    {"id": "zeta",      "methods": ["GET"], "pathPrefix": "/a/b", "upstream": "http://z.internal"},
	    {"id": "alpha",     "methods": ["GET"], "pathPrefix": "/a/b", "upstream": "http://a.internal"}
	  ]
	}`
	saved := saveConfigJSON(t, config)

	// GET: conflict stays a conflict, candidates stay exact and sorted.
	res := assertCLISameResult(t, config, saved, `{"method":"GET","target":"/a/b/x"}`)
	f := decodeCLIFailure(t, res)
	if f.Code != "route_conflict" {
		t.Fatalf("GET code = %q, want route_conflict (never invalid_config after a save)", f.Code)
	}
	if got := strings.Join(f.Candidates, ","); got != "alpha,zeta" {
		t.Fatalf("GET candidates = %v, want [alpha zeta] with no wildcard or shorter-prefix route", f.Candidates)
	}

	// POST: no concrete rivalry at /a/b, so the wildcard succeeds even
	// though GET conflicts there.
	res = assertCLISameResult(t, config, saved, `{"method":"POST","target":"/a/b/x"}`)
	if res.exitCode != 0 {
		t.Fatalf("POST exit = %d, want 0: %s", res.exitCode, res.stderr)
	}
	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, res.stdout, "stdout", &success)
	if success.RouteID != "wild-long" || success.UpstreamURL != "http://wild.internal/w/x" {
		t.Fatalf("POST got %+v, want wild-long / http://wild.internal/w/x", success)
	}

	// GET under the shorter prefix still resolves to the shorter route.
	assertCLISameResult(t, config, saved, `{"method":"GET","target":"/a/other"}`)
}
