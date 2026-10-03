package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These tests exercise resolve the way a user does: a config file argument,
// one JSON request on stdin, and the observable exit status / stdout / stderr
// of the whole command. They never open a network connection and do not need
// the upstreams to exist, so they reproduce deterministically offline.

// helperEnv guards TestHelperProcess: only a child spawned with this variable
// set hands its arguments over to the real main; in an ordinary `go test`
// run the test is a no-op.
const helperEnv = "CONTRACTSENTINEL_HELPER_PROCESS"

// TestHelperProcess is the re-executed test binary: arguments after "--"
// become the command's own os.Args, then main runs as normal (including its
// non-zero os.Exit on failure, which the parent observes via exit status).
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	for i, a := range os.Args {
		if a == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	main()
	os.Exit(0)
}

// resolveResult is everything the parent can observe from one resolve run.
type resolveResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
}

// runResolveCLI writes config to a temp file, spawns the helper test binary
// with "resolve <config>" and feeds the request on stdin.
func runResolveCLI(t *testing.T, config, request string) resolveResult {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "resolve", configPath)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdin = strings.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("run resolve helper: %v", err)
		}
	}
	return resolveResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), exitCode: exitCode}
}

// decodeOneJSON decodes exactly one JSON value and requires nothing but
// trailing whitespace afterwards, so "one JSON object in the stream" is
// asserted instead of merely "a prefix parses".
func decodeOneJSON(t *testing.T, data []byte, what string, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s is not a single JSON object: %v\n%s", what, err, data)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("%s contains more than one JSON value: %v\n%s", what, err, data)
	}
}

const cliSuccessConfig = `{
  "routes": [
    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"}
  ]
}`

const cliSuccessRequest = `{"method":"GET","target":"/api/items?a=1&a=&x=%2f+&flag"}`

func TestResolveCLISuccess(t *testing.T) {
	res := runResolveCLI(t, cliSuccessConfig, cliSuccessRequest)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
	}
	if len(res.stderr) != 0 {
		t.Fatalf("stderr = %q, want empty", res.stderr)
	}

	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, res.stdout, "stdout", &success)

	if success.RouteID != "api" {
		t.Errorf("routeId = %q, want api", success.RouteID)
	}
	wantURL := "http://api.internal/v1/items?a=1&a=&x=%2f+&flag"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}

	// The raw query must survive byte for byte: '&' is emitted literally
	// (HTML escaping off), and the stream is just the one compact result
	// object with no demo, usage or debug text mixed in.
	if !bytes.Contains(res.stdout, []byte("&")) {
		t.Errorf("stdout should contain raw '&': %s", res.stdout)
	}
	if bytes.Contains(res.stdout, []byte("\\u0026")) {
		t.Errorf("stdout must not unicode-escape '&': %s", res.stdout)
	}
	var keys map[string]json.RawMessage
	decodeOneJSON(t, res.stdout, "stdout", &keys)
	if len(keys) != 2 || keys["routeId"] == nil || keys["upstreamURL"] == nil {
		t.Errorf("stdout should be exactly {routeId, upstreamURL}, got keys: %v", keys)
	}
}

func TestResolveCLIInvalidConfigRejectedEvenWhenFirstRouteHits(t *testing.T) {
	// A GET /api request would hit route 1; route 2 ("admin") can never
	// match, but its second queryTransforms rule uses the unsupported
	// "delete" op, which must reject the whole configuration up front.
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://admin.internal",
	     "queryTransforms": [
	       {"op": "set", "name": "a", "value": "1"},
	       {"op": "delete", "name": "x"}
	     ]}
	  ]
	}`
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
		t.Errorf("code = %q, want invalid_config", fail.Code)
	}
	if fail.Reason == "" {
		t.Fatal("reason must be non-empty")
	}
	for _, want := range []string{"route 2", `"admin"`, "rule 2"} {
		if !strings.Contains(fail.Reason, want) {
			t.Errorf("reason = %q, want substring %q (route position, id and rule index)", fail.Reason, want)
		}
	}
}

// TestResolveCLIRouteFieldTypeLocated rejects valid JSON whose second route
// has a wrong-typed methods field, even when the request would hit the first
// route; the stderr reason must name route 2 and its orders id and say
// methods must be an array, instead of blaming the whole document's JSON.
func TestResolveCLIRouteFieldTypeLocated(t *testing.T) {
	badConfig := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "orders", "methods": "GET", "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	res := runResolveCLI(t, badConfig, cliSuccessRequest)

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
		t.Errorf("code = %q, want invalid_config", fail.Code)
	}
	if strings.Contains(fail.Reason, "not valid JSON") {
		t.Fatalf("field type error must not read as a JSON syntax failure: %q", fail.Reason)
	}
	for _, want := range []string{"route 2", `"orders"`, "methods must be an array"} {
		if !strings.Contains(fail.Reason, want) {
			t.Errorf("reason = %q, want substring %q", fail.Reason, want)
		}
	}

	// After the second route is repaired to an array, the same request
	// resolves normally and the first route still matches.
	fixedConfig := strings.Replace(badConfig, `"methods": "GET", "pathPrefix": "/api/orders"`,
		`"methods": ["GET"], "pathPrefix": "/api/orders"`, 1)
	ok := runResolveCLI(t, fixedConfig, cliSuccessRequest)
	if ok.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", ok.exitCode, ok.stderr)
	}
	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, ok.stdout, "stdout", &success)
	if success.RouteID != "api" || success.UpstreamURL != "http://api.internal/v1/items?a=1&a=&x=%2f+&flag" {
		t.Fatalf("got %+v", success)
	}

	// A numeric entry inside an otherwise legal methods array is attributed
	// to that route's methods, and must name the entry that failed.
	numConfig := strings.Replace(badConfig, `"methods": "GET", "pathPrefix": "/api/orders"`,
		`"methods": ["GET", 1], "pathPrefix": "/api/orders"`, 1)
	num := runResolveCLI(t, numConfig, cliSuccessRequest)
	if num.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	var numFail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, num.stderr, "stderr", &numFail)
	if numFail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", numFail.Code)
	}
	for _, want := range []string{"route 2", `"orders"`, "methods entry 2 must be a string"} {
		if !strings.Contains(numFail.Reason, want) {
			t.Errorf("reason = %q, want substring %q", numFail.Reason, want)
		}
	}
}

// renameTwoRoutesConfig gives two routes that both match /api requests: a
// wide wildcard and a longer concrete route. Each carries a different rename,
// so a resolved request shows which route's transforms actually ran.
const renameTwoRoutesConfig = `{
  "routes": [
    {"id": "wide", "methods": ["*"], "pathPrefix": "/api",
     "upstream": "http://wide.internal/w",
     "queryTransforms": [{"op": "rename", "name": "old", "to": "wide"}]},
    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
     "upstream": "http://orders.internal",
     "queryTransforms": [{"op": "rename", "name": "old", "to": "new"}]}
  ]
}`

// assertResolveSuccess runs one resolve and checks the full success contract
// at the command boundary: exit 0, empty stderr, exactly one
// {routeId, upstreamURL} JSON object on stdout with '&' never HTML-escaped.
func assertResolveSuccess(t *testing.T, res resolveResult) struct {
	RouteID     string `json:"routeId"`
	UpstreamURL string `json:"upstreamURL"`
} {
	t.Helper()
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
	}
	if len(res.stderr) != 0 {
		t.Fatalf("stderr = %q, want empty", res.stderr)
	}
	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, res.stdout, "stdout", &success)
	var keys map[string]json.RawMessage
	decodeOneJSON(t, res.stdout, "stdout", &keys)
	if len(keys) != 2 || keys["routeId"] == nil || keys["upstreamURL"] == nil {
		t.Fatalf("stdout should be exactly {routeId, upstreamURL}, got keys: %v", keys)
	}
	if bytes.Contains(res.stdout, []byte("\\u0026")) {
		t.Fatalf("stdout must not unicode-escape '&': %s", res.stdout)
	}
	return success
}

// TestResolveCLIRenameQueryTransform drives the headline rename behavior the
// way a user does: the rule is read from the config file, the request comes
// from stdin, and the renamed query is observed inside upstreamURL. Sources
// are recognized by decoded name (including "%6Fld"), every duplicate is
// renamed in place, an existing target parameter survives, and values, the
// no-equals form, empty values and the trailing empty fragment all stay as
// they were.
func TestResolveCLIRenameQueryTransform(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
	     "upstream": "http://orders.internal",
	     "queryTransforms": [{"op": "rename", "name": "old", "to": "new"}]}
	  ]
	}`
	request := `{"method":"GET","target":"/api/orders/7?old=1&new=9&%6Fld=%2f+a=b&old&x=&"}`

	success := assertResolveSuccess(t, runResolveCLI(t, config, request))
	if success.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", success.RouteID)
	}
	wantURL := "http://orders.internal/7?new=1&new=9&new=%2f+a=b&new&x=&"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLIRenameNameMatchingAndEncoding covers name comparison and
// re-encoding at the command boundary: '+' and percent-encoded spaces name
// the same parameter, matching is case-sensitive, a new name with spaces or
// non-ASCII bytes is encoded like set, fragments that do not hit keep their
// bytes, and renaming a name to itself must not re-encode existing names.
func TestResolveCLIRenameNameMatchingAndEncoding(t *testing.T) {
	rootConfig := func(rule string) string {
		return `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
			`"upstream":"http://h.internal/base","queryTransforms":[` + rule + `]}]}`
	}
	cases := []struct {
		name    string
		rule    string
		target  string
		wantURL string
	}{
		{
			name:    "plus and percent encoded spaces are the same source name",
			rule:    `{"op":"rename","name":"a b","to":"c d"}`,
			target:  "/p?a+b=1&a%20b=2",
			wantURL: "http://h.internal/base/p?c%20d=1&c%20d=2",
		},
		{
			name:    "matching is case sensitive",
			rule:    `{"op":"rename","name":"old","to":"new"}`,
			target:  "/p?OLD=1&old=2",
			wantURL: "http://h.internal/base/p?OLD=1&new=2",
		},
		{
			name:    "new name with space and non ASCII is encoded, unmatched bytes stay",
			rule:    `{"op":"rename","name":"old","to":"新 name"}`,
			target:  "/p?old=1&keep=A%42+z",
			wantURL: "http://h.internal/base/p?%E6%96%B0%20name=1&keep=A%42+z",
		},
		{
			name:    "same source and target preserves existing name encodings byte for byte",
			rule:    `{"op":"rename","name":"a b","to":"a b"}`,
			target:  "/p?a+b=1&a%20b=2&x=",
			wantURL: "http://h.internal/base/p?a+b=1&a%20b=2&x=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, rootConfig(tc.rule), request))
			if success.RouteID != "root" {
				t.Errorf("routeId = %q, want root", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.wantURL)
			}
		})
	}
}

// TestResolveCLIRenameOnlyOnSelectedRoute proves the rename belongs to the
// finally matched route: it neither changes prefix selection nor upstream
// path joining, and a losing route's rename is never executed.
func TestResolveCLIRenameOnlyOnSelectedRoute(t *testing.T) {
	// GET /api/orders/7 selects the longer concrete route; the wildcard
	// route's old->wide rename must not touch the query, and the /7 join
	// onto a host-only upstream is unchanged.
	longer := assertResolveSuccess(t, runResolveCLI(t, renameTwoRoutesConfig,
		`{"method":"GET","target":"/api/orders/7?old=1&new=9&old"}`))
	if longer.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders (longest prefix wins)", longer.RouteID)
	}
	if want := "http://orders.internal/7?new=1&new=9&new"; longer.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", longer.UpstreamURL, want)
	}

	// A request only the wide route matches runs that route's own rename and
	// joins onto its base path normally.
	wide := assertResolveSuccess(t, runResolveCLI(t, renameTwoRoutesConfig,
		`{"method":"GET","target":"/api/x?old=1"}`))
	if wide.RouteID != "wide" {
		t.Errorf("routeId = %q, want wide", wide.RouteID)
	}
	if want := "http://wide.internal/w/x?wide=1"; wide.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", wide.UpstreamURL, want)
	}
}

// TestResolveCLIRenameThenSetMergesInConfigOrder checks rule ordering through
// the CLI: a set on the new name after the rename merges the pre-existing
// target parameter and the renamed sources together at the first occurrence,
// while unrelated parameters keep their order.
func TestResolveCLIRenameThenSetMergesInConfigOrder(t *testing.T) {
	config := `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
		`"upstream":"http://h.internal/base","queryTransforms":[
		  {"op":"rename","name":"old","to":"new"},
		  {"op":"set","name":"new","value":"z"}
		]}]}`
	success := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"GET","target":"/p?new=1&old=2&x=3"}`))
	if success.RouteID != "root" {
		t.Errorf("routeId = %q, want root", success.RouteID)
	}
	wantURL := "http://h.internal/base/p?new=z&x=3"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLIRenameInvalidToRejectsConfig exercises the rename boundary at
// the command boundary: a missing, empty or non-string "to" invalidates the
// whole configuration even though the offending route can never match the
// request. Failure leaves stdout empty and puts one JSON error on stderr whose
// reason names the route position, the route's id and the 1-based rule index.
func TestResolveCLIRenameInvalidToRejectsConfig(t *testing.T) {
	cases := []struct {
		name string
		bad  string
	}{
		{"to missing", `{"op":"rename","name":"a"}`},
		{"to empty", `{"op":"rename","name":"a","to":""}`},
		{"to numeric", `{"op":"rename","name":"a","to":7}`},
		{"to null", `{"op":"rename","name":"a","to":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Route 1 ("hit") serves every request via the root prefix;
			// route 2 ("admin") never matches. A valid set rule precedes the
			// bad rename, pinning the reported location to rule 2.
			config := `{
			  "routes": [
			    {"id": "hit", "methods": ["*"], "pathPrefix": "/",
			     "upstream": "http://hit.internal"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin",
			     "upstream": "http://admin.internal",
			     "queryTransforms": [
			       {"op": "set", "name": "a", "value": "1"},
			       ` + tc.bad + `
			     ]}
			  ]
			}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/ping?old=1"}`)

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
				t.Errorf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "rule 2"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q (route position, id and 1-based rule index)",
						fail.Reason, want)
				}
			}
		})
	}
}

func TestResolveCLIRouteConflict(t *testing.T) {
	// alpha and zeta both concretely accept GET at the same /api prefix
	// with no longer prefix to win; the same-prefix wildcard route must not
	// appear among the final candidates.
	config := `{
	  "routes": [
	    {"id": "zeta",  "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://z.internal/v1"},
	    {"id": "alpha", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://a.internal/v1"},
	    {"id": "wild",  "methods": ["*"],   "pathPrefix": "/api", "upstream": "http://w.internal/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, cliSuccessRequest)

	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
	}

	var fail struct {
		Code       string   `json:"code"`
		Reason     string   `json:"reason"`
		Candidates []string `json:"candidates"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "route_conflict" {
		t.Errorf("code = %q, want route_conflict", fail.Code)
	}
	if fail.Reason == "" {
		t.Fatal("reason must be non-empty")
	}
	wantCandidates := []string{"alpha", "zeta"}
	if !reflect.DeepEqual(fail.Candidates, wantCandidates) {
		t.Errorf("candidates = %v, want %v (sorted, wildcard excluded)", fail.Candidates, wantCandidates)
	}
}
