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

// cliRenameConfig is a route whose only transform renames old to new.
const cliRenameConfig = `{
  "routes": [
    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1",
     "queryTransforms": [{"op": "rename", "name": "old", "to": "new"}]}
  ]
}`

// TestResolveCLIRenameQueryTransform drives the headline rename case through
// the real command: the config is read from a file, the request from stdin,
// and the rewritten query is observed in the stdout JSON. Sources are matched
// by their decoded name ("%6Fld" is "old"), every repeated source is renamed
// in place, an existing "new" survives alongside, and values, the no-equals
// form, empty values and the trailing empty fragment all stay byte for byte.
func TestResolveCLIRenameQueryTransform(t *testing.T) {
	request := `{"method":"GET","target":"/api/items?old=1&new=9&%6Fld=%2f+a=b&old&x=&"}`
	res := runResolveCLI(t, cliRenameConfig, request)

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
	wantURL := "http://api.internal/v1/items?new=1&new=9&new=%2f+a=b&new&x=&"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}

	// The rewritten query keeps raw '&' separators (no HTML escaping) and the
	// whole stdout is exactly the one {routeId, upstreamURL} object.
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

// TestResolveCLIRenameNameMatchingAndEncoding covers name comparison and
// output encoding through the CLI: '+' and percent-encoded spaces name the
// same parameter and both are renamed in place; matching is case-sensitive;
// a new name with a space or non-ASCII bytes is encoded like a set value;
// fragments that do not hit keep their original bytes and order.
func TestResolveCLIRenameNameMatchingAndEncoding(t *testing.T) {
	configWith := func(rule string) string {
		return `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api",` +
			`"upstream":"http://api.internal/v1","queryTransforms":[` + rule + `]}]}`
	}
	cases := []struct {
		name      string
		rule      string
		query     string
		wantQuery string
	}{
		{
			name:      "plus and percent-escaped spaces are the same name; matching is case-sensitive",
			rule:      `{"op":"rename","name":"a b","to":"c d"}`,
			query:     "a+b=1&a%20b=2&A+b=3&z",
			wantQuery: "?c%20d=1&c%20d=2&A+b=3&z",
		},
		{
			name:      "new name with space and non-ASCII bytes is encoded; non-hit fragments stay verbatim",
			rule:      `{"op":"rename","name":"old","to":"新 x"}`,
			query:     "old=1&keep=%2f+a=b&old",
			wantQuery: "?%E6%96%B0%20x=1&keep=%2f+a=b&%E6%96%B0%20x",
		},
		{
			name:      "no source parameter leaves the whole query byte for byte",
			rule:      `{"op":"rename","name":"old","to":"new"}`,
			query:     "a=1&%62=2&",
			wantQuery: "?a=1&%62=2&",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"/api/items?` + tc.query + `"}`
			res := runResolveCLI(t, configWith(tc.rule), request)
			if res.exitCode != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
			}
			if len(res.stderr) != 0 {
				t.Fatalf("stderr = %q, want empty", res.stderr)
			}
			var success struct {
				UpstreamURL string `json:"upstreamURL"`
			}
			decodeOneJSON(t, res.stdout, "stdout", &success)
			wantURL := "http://api.internal/v1/items" + tc.wantQuery
			if success.UpstreamURL != wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
			}
		})
	}
}

// TestResolveCLIRenameOnlyOnMatchedRoute proves the rewrite is bound to the
// route that actually wins: the wildcard "/" route also carries a rename that
// must not run, and route selection, prefix matching and upstream path
// joining are unchanged by either route's transforms.
func TestResolveCLIRenameOnlyOnMatchedRoute(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1",
	     "queryTransforms": [{"op": "rename", "name": "old", "to": "new"}]},
	    {"id": "root", "methods": ["*"], "pathPrefix": "/", "upstream": "http://fallback.internal/base/",
	     "queryTransforms": [{"op": "rename", "name": "new", "to": "zz"}]}
	  ]
	}`

	// GET /api wins on longest prefix + concrete method; the losing root
	// route's new->zz rename must not be applied.
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/orders/7?old=1&new=9"}`)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
	}
	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, res.stdout, "stdout", &success)
	wantURL := "http://api.internal/v1/orders/7?new=1&new=9"
	if success.RouteID != "api" || success.UpstreamURL != wantURL {
		t.Fatalf("got %+v, want routeId api and %q", success, wantURL)
	}

	// Matching the prefix itself leaves exactly one slash at the junction.
	exact := runResolveCLI(t, config, `{"method":"GET","target":"/api?old=1"}`)
	if exact.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", exact.exitCode, exact.stderr)
	}
	decodeOneJSON(t, exact.stdout, "stdout", &success)
	if success.RouteID != "api" || success.UpstreamURL != "http://api.internal/v1/?new=1" {
		t.Fatalf("got %+v, want joined URL with one junction slash", success)
	}
}

// TestResolveCLIRenameThenSetChainsInConfigOrder verifies rules run in array
// order: a set of the new name after the rename merges the pre-existing
// target parameter and every renamed source into the first hit's position,
// while the other parameters keep their order; the reverse rule order yields
// a different result, proving the order is configuration order.
func TestResolveCLIRenameThenSetChainsInConfigOrder(t *testing.T) {
	configWith := func(rules string) string {
		return `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api",` +
			`"upstream":"http://api.internal/v1","queryTransforms":[` + rules + `]}]}`
	}
	cases := []struct {
		name      string
		rules     string
		wantQuery string
	}{
		{
			name:      "rename then set merges original and renamed at first occurrence",
			rules:     `{"op":"rename","name":"old","to":"new"},{"op":"set","name":"new","value":"z"}`,
			wantQuery: "?new=z&x=3",
		},
		{
			name:      "set then rename keeps the renamed value verbatim as a second parameter",
			rules:     `{"op":"set","name":"new","value":"z"},{"op":"rename","name":"old","to":"new"}`,
			wantQuery: "?new=z&new=2&x=3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"/api/p?new=1&old=2&x=3"}`
			res := runResolveCLI(t, configWith(tc.rules), request)
			if res.exitCode != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
			}
			if len(res.stderr) != 0 {
				t.Fatalf("stderr = %q, want empty", res.stderr)
			}
			var success struct {
				UpstreamURL string `json:"upstreamURL"`
			}
			decodeOneJSON(t, res.stdout, "stdout", &success)
			if want := "http://api.internal/v1/p" + tc.wantQuery; success.UpstreamURL != want {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, want)
			}
		})
	}
}

// TestResolveCLIRenameSameNameKeepsNameEncodings checks the edge where source
// and target are identical: existing name encodings ("+" and "%20" for the
// same decoded name) are preserved byte for byte instead of being re-encoded.
func TestResolveCLIRenameSameNameKeepsNameEncodings(t *testing.T) {
	config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api",` +
		`"upstream":"http://api.internal/v1","queryTransforms":` +
		`[{"op":"rename","name":"a b","to":"a b"}]}]}`
	request := `{"method":"GET","target":"/api/items?a+b=1&a%20b=2&x="}`
	res := runResolveCLI(t, config, request)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
	}
	var success struct {
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, res.stdout, "stdout", &success)
	wantURL := "http://api.internal/v1/items?a+b=1&a%20b=2&x="
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLIRenameInvalidToRejectsConfig drives the invalid_config
// boundary for a rename "to" that is missing, empty or not a string: the bad
// rule sits on route 2 ("admin"), which the request can never hit, yet the
// whole configuration must be rejected before resolution. stdout stays
// empty; stderr carries one JSON whose reason names the route position, the
// existing id and the 1-based rule index; the exit status is non-zero.
func TestResolveCLIRenameInvalidToRejectsConfig(t *testing.T) {
	cases := []struct {
		name    string
		badRule string
		want    string
	}{
		{"missing to", `{"op":"rename","name":"old"}`, "rename requires a non-empty string to"},
		{"empty to", `{"op":"rename","name":"old","to":""}`, "to must be a non-empty string"},
		{"numeric to", `{"op":"rename","name":"old","to":9}`, "to must be a non-empty string"},
		{"null to", `{"op":"rename","name":"old","to":null}`, "to must be a non-empty string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://admin.internal",
			     "queryTransforms": [
			       {"op": "set", "name": "keep", "value": "1"},
			       ` + tc.badRule + `
			     ]}
			  ]
			}`
			// The request hits route 1; route 2 with the bad rule never matches.
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
			for _, want := range []string{"route 2", `"admin"`, "rule 2", tc.want} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q (route position, id, rule index and detail)",
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
