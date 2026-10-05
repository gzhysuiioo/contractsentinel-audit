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

// TestResolveCLISetSpecialCharNames drives the set transform with names and
// values that contain '&', '=', '%' and '+' the way a user does: the rule
// comes from the config file, the request from stdin, and the merged query is
// observed inside upstreamURL. The rule's name and value are literal text;
// on the wire only raw '&' separates fragments and the first raw '=' splits
// a fragment, so the encoded "&" and "=" never create extra parameters. Both
// sources of the same decoded name merge at the first hit's position while
// untouched fragments, the empty fragment and their order keep their bytes.
func TestResolveCLISetSpecialCharNames(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
	     "upstream": "http://orders.internal",
	     "queryTransforms": [{"op": "set", "name": "a&b=c", "value": "x&y=z"}]}
	  ]
	}`
	request := `{"method":"GET","target":"/api/orders/7?keep=%2f+&a%26b%3dc=1&&a%26b%3Dc=2&tail="}`

	success := assertResolveSuccess(t, runResolveCLI(t, config, request))
	if success.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", success.RouteID)
	}
	wantURL := "http://orders.internal/7?keep=%2f+&a%26b%3Dc=x%26y%3Dz&&tail="
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLISetInvalidEscapeNoPartialSuccess pairs a working set rule
// with a request whose query holds a malformed percent escape next to a
// replaceable parameter: the whole request is invalid_request, stdout stays
// completely empty and no partially rewritten upstreamURL is emitted.
func TestResolveCLISetInvalidEscapeNoPartialSuccess(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
	     "upstream": "http://orders.internal",
	     "queryTransforms": [{"op": "set", "name": "a&b=c", "value": "x&y=z"}]}
	  ]
	}`
	res := runResolveCLI(t, config,
		`{"method":"GET","target":"/api/orders/7?a%26b%3dc=1&bad%zz=2"}`)

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
	if fail.Code != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", fail.Code)
	}
	if !strings.Contains(fail.Reason, "percent escape") {
		t.Errorf("reason = %q, want a percent-escape reason", fail.Reason)
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

// TestResolveCLIRequestErrorReasons exercises how malformed requests are
// explained at the command boundary: broken JSON is a parse failure, a legal
// non-object document says the request must be an object, and a legal object
// with a wrong-typed field names the field and the received type. Every
// failure still exits non-zero, leaves stdout empty and emits one JSON error.
func TestResolveCLIRequestErrorReasons(t *testing.T) {
	cases := []struct {
		name      string
		request   string
		want      []string
		forbidden []string
	}{
		{
			name:      "syntactically broken JSON",
			request:   `{"method":"GET",`,
			want:      []string{"not valid JSON"},
			forbidden: []string{"method", "target"},
		},
		{
			name:      "top level array is legal JSON but the wrong shape",
			request:   `["GET","/api"]`,
			want:      []string{"must be a JSON object"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name:      "top level null is legal JSON but the wrong shape",
			request:   `null`,
			want:      []string{"must be a JSON object"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name:      "numeric method is a field type error",
			request:   `{"method":42,"target":"/api"}`,
			want:      []string{"method must be a string", "got a number"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name:      "array target is a field type error",
			request:   `{"method":"GET","target":[]}`,
			want:      []string{"target must be a string", "got an array"},
			forbidden: []string{"not valid JSON", "start with /"},
		},
		{
			name:      "null method is a type error, not a missing method",
			request:   `{"method":null,"target":"/api"}`,
			want:      []string{"method must be a string", "got null"},
			forbidden: []string{"method is required"},
		},
		{
			name:      "both fields wrong report method regardless of key order",
			request:   `{"target":[],"method":42}`,
			want:      []string{"method must be a string"},
			forbidden: []string{"target must be a string"},
		},
		{
			name:      "empty string is content validated, not type checked",
			request:   `{"method":"GET","target":"/api%2"}`,
			want:      []string{"invalid percent escape"},
			forbidden: []string{"must be a string"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runResolveCLI(t, cliSuccessConfig, tc.request)
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
			if fail.Code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", fail.Code)
			}
			for _, want := range tc.want {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, bad := range tc.forbidden {
				if strings.Contains(fail.Reason, bad) {
					t.Errorf("reason = %q must not contain %q", fail.Reason, bad)
				}
			}
		})
	}

	// A bad config is reported before the request is even examined, so a
	// broken config paired with a broken request still yields invalid_config.
	badConfig := `{"routes":[{"id":"x","methods":"GET","pathPrefix":"/a","upstream":"http://h"}]}`
	res := runResolveCLI(t, badConfig, `{not json`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config to take priority", fail.Code)
	}
}

// TestResolveCLIConfigShapeErrors exercises configs that are legal JSON but
// the wrong structure at the command boundary: a non-object top level
// (including null) says the config must be a JSON object; a non-array routes
// field (including null) says routes must be an array; a null element after a
// route the request would hit rejects the whole config by element position.
// None of these may be reported as a JSON syntax failure, stdout stays empty,
// and a structurally invalid config wins over an invalid request.
func TestResolveCLIConfigShapeErrors(t *testing.T) {
	cases := []struct {
		name      string
		config    string
		want      []string
		forbidden []string
	}{
		{
			name:      "top level array",
			config:    `[]`,
			want:      []string{"config must be a JSON object", "got an array"},
			forbidden: []string{"not valid JSON", "route "},
		},
		{
			name:      "top level null",
			config:    `null`,
			want:      []string{"config must be a JSON object", "got null"},
			forbidden: []string{"not valid JSON", "route "},
		},
		{
			name:      "top level string",
			config:    `"routes"`,
			want:      []string{"config must be a JSON object", "got a string"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name:      "routes null is a type error, not an empty config",
			config:    `{"routes":null}`,
			want:      []string{"routes must be an array", "got null"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name:      "routes object",
			config:    `{"routes":{}}`,
			want:      []string{"routes must be an array", "got an object"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name: "null element after a route the request would match",
			config: `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    null
			  ]
			}`,
			want:      []string{"route 2", "route entry must be an object", "got null"},
			forbidden: []string{"not valid JSON", "id"},
		},
		{
			name:      "boolean element as the only route",
			config:    `{"routes":[true]}`,
			want:      []string{"route 1", "route entry must be an object", "got a boolean"},
			forbidden: []string{"not valid JSON", "id"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runResolveCLI(t, tc.config, cliSuccessRequest)
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
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			for _, bad := range tc.forbidden {
				if strings.Contains(fail.Reason, bad) {
					t.Errorf("reason = %q must not contain %q", fail.Reason, bad)
				}
			}
		})
	}

	// A structurally wrong config is reported before the request is even
	// examined, so routes:null paired with broken-JSON request still yields
	// invalid_config.
	res := runResolveCLI(t, `{"routes":null}`, `{not json`)
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
	if !strings.Contains(fail.Reason, "routes must be an array") {
		t.Fatalf("reason = %q, want the routes type error", fail.Reason)
	}

	// A broken-JSON config is still a parse failure at the boundary, even
	// though the fragment looks like it starts a routes array.
	broken := runResolveCLI(t, `{"routes":[ broken`, cliSuccessRequest)
	if broken.exitCode == 0 {
		t.Fatal("broken config must exit non-zero")
	}
	var brokenFail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, broken.stderr, "stderr", &brokenFail)
	if brokenFail.Code != "invalid_config" || !strings.Contains(brokenFail.Reason, "not valid JSON") {
		t.Fatalf("got %+v, want invalid_config parse failure", brokenFail)
	}
}

// TestResolveCLIEncodedBasePathJoin drives the encoded-base-path join the way
// a user does: the upstream carries a percent-encoded userinfo, an IPv6 host
// with brackets, a port and a base path with encoded slashes and trailing
// slash runs. Only the junction run collapses to one slash; every other byte
// of the configured upstream and the request target must reach upstreamURL
// unchanged. The routes define no queryTransforms, so the raw query (empty
// question mark included) is preserved verbatim. Everything runs offline:
// the upstream hosts never need to exist.
func TestResolveCLIEncodedBasePathJoin(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "enc",  "methods": ["GET"], "pathPrefix": "/api", "upstream": "https://user:p%40ss@[2001:db8::1]:8443/v%2f//base%2f///"},
	    {"id": "root", "methods": ["*"],   "pathPrefix": "/",    "upstream": "https://root.internal/v%2f//base%2f///"}
	  ]
	}`
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "junction collapse leaves encoded content byte for byte",
			target:   "/api//%2F/x//y/?a=1&a=&flag",
			routeID:  "enc",
			upstream: "https://user:p%40ss@[2001:db8::1]:8443/v%2f//base%2f/%2F/x//y/?a=1&a=&flag",
		},
		{
			name:     "request equal to the prefix keeps encoded base and one slash",
			target:   "/api",
			routeID:  "enc",
			upstream: "https://user:p%40ss@[2001:db8::1]:8443/v%2f//base%2f/",
		},
		{
			name:     "empty question mark stays distinct from no query",
			target:   "/api?",
			routeID:  "enc",
			upstream: "https://user:p%40ss@[2001:db8::1]:8443/v%2f//base%2f/?",
		},
		{
			name:     "root prefix receiving the root path keeps the encoded base",
			target:   "/",
			routeID:  "root",
			upstream: "https://root.internal/v%2f//base%2f/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, config, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}
}

// TestResolveCLIInvalidUpstreamEscapeRejectsConfig rejects a config whose
// second route carries an invalid percent escape in its upstream path, even
// though the request would hit the valid first route: the exit status is
// non-zero, stdout stays completely empty and stderr holds one JSON error
// whose reason locates the offending route by position and id.
func TestResolveCLIInvalidUpstreamEscapeRejectsConfig(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://admin.internal/base%zz"}
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
	for _, want := range []string{"route 2", `"admin"`, "upstream"} {
		if !strings.Contains(fail.Reason, want) {
			t.Errorf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
}

func TestResolveCLIBracketedHostMustBeIPv6(t *testing.T) {
	// Brackets may enclose only a legal IPv6 literal. A name or an IPv4
	// address in brackets on a route the request never reaches still rejects
	// the whole config up front: non-zero exit, empty stdout and one JSON
	// error on stderr whose reason names the route position, its id and the
	// upstream field, and says the bracketed host is not a legal IPv6 address
	// — it must not be reported as broken config JSON.
	cases := []struct {
		name     string
		upstream string
	}{
		{"name in brackets", "http://[not-an-ip]/v1"},
		{"bare ipv4 in brackets", "http://[127.0.0.1]:8080/v1"},
		{"empty brackets", "http://[]/v1"},
		{"malformed ipv6", "http://[2001:db8:::1]/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			// The request hits the valid first route only.
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
			for _, want := range []string{"route 2", `"admin"`, "upstream", "IPv6"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Errorf("a bad bracketed host is a content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}

	// A malformed request paired with a bad bracketed-host config still
	// reports invalid_config: config validation precedes request parsing.
	badConfig := `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/x","upstream":"http://[not-an-ip]/v1"}]}`
	res := runResolveCLI(t, badConfig, `{not json`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config to take priority", fail.Code)
	}
}

// TestResolveCLIUnbracketedIPv6Host drives the missing-bracket rule at the
// command boundary: a full, compressed or IPv4-tail IPv6 literal written
// without square brackets — with a digit suffix, a zone or userinfo too —
// rejects the whole config up front, even on a route the request never
// hits. Non-zero exit, completely empty stdout and one JSON invalid_config
// error on stderr whose reason names the route position, its id and the
// upstream field and says the IPv6 host is missing brackets; it must not be
// reported as broken config JSON, and an invalid request still loses to the
// config error.
func TestResolveCLIUnbracketedIPv6Host(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
	}{
		{"compressed address under base path", "http://2001:db8::1/base"},
		{"compressed address with trailing digits", "http://::1:8080/base"},
		{"embedded ipv4 tail", "http://::ffff:192.0.2.1/base"},
		{"full form", "http://2001:0db8:0000:0000:0000:0000:0000:0001/base"},
		{"address and trailing digits, no base path", "http://fe80::1:8080"},
		{"percent encoded zone without brackets", "http://fe80::1%25eth0/base"},
		{"encoded userinfo and a port-like suffix", "https://user:p%40ss@2001:db8::1:8443/base"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			// The request hits the valid first route only.
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
			for _, want := range []string{"route 2", `"admin"`, "upstream", "IPv6", "bracket"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Errorf("an unbracketed IPv6 host is a content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}

	// An unbracketed-IPv6 config wins over an invalid request: config
	// validation precedes request parsing, so even broken request JSON yields
	// invalid_config.
	config := `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/x","upstream":"http://2001:db8::1/base"}]}`
	res := runResolveCLI(t, config, `{not json`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config to take priority", fail.Code)
	}
}

// TestResolveCLIUnbracketedHostExtraColons drives the extra-colon rule at the
// command boundary: an unbracketed host part may carry at most one colon (the
// port separator), so upstreams such as "http://api:internal:8080/base" or
// "http://name:part:80" reject the whole config up front — even on a route
// the request never hits, and even though the bytes are not a legal IPv6
// literal either. Non-zero exit, completely empty stdout and one JSON
// invalid_config error on stderr whose reason names the route position, its
// id and the upstream value and says the unbracketed host part contains too
// many colons; it must not be reported as broken config JSON.
func TestResolveCLIUnbracketedHostExtraColons(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
	}{
		{"name with two port-like segments", "http://api:internal:8080/base"},
		{"name with a text segment and a port", "http://name:part:80"},
		{"empty segment between colons", "http://host.internal::/base"},
		{"ipv4 with an extra segment", "http://192.0.2.1:80:8080/base"},
		{"userinfo before a multi-colon host", "http://user:pw@api:internal:8080/base"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			// The request hits the valid first route only.
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
			for _, want := range []string{"route 2", `"admin"`, "upstream", "colon"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Errorf("a multi-colon host is a content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}

	// The reported single-route case must fail at the command boundary too:
	// GET /api/items is never resolved against the bad upstream.
	config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api:internal:8080/base"}]}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", fail.Code)
	}
}

// TestResolveCLIValidIPv6Upstreams drives the legal IPv6 spellings at the
// command boundary: full, compressed and IPv4-tail literals, a port,
// percent-encoded userinfo and a percent-encoded zone must resolve and keep
// the configured bytes verbatim; ordinary domains and bare IPv4 hosts keep
// their existing behavior.
// TestResolveCLIBracketedHostShape drives the whole-host bracket grammar at
// the command boundary: brackets must wrap the whole host exactly once, so a
// repeated bracket group ("[::1][::2]"), a stray ']' ("[::1]extra]") or junk
// between the address and the port rejects the whole config up front — even
// when userinfo or a port is present and even though the request only hits
// the valid first route. Failure keeps the usual contract: non-zero exit,
// completely empty stdout and one JSON invalid_config error on stderr whose
// reason names the route position, its id and the upstream field and calls
// the bracket spelling illegal rather than blaming the document's JSON.
func TestResolveCLIBracketedHostShape(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
	}{
		{"repeated bracket group", "http://[::1][::2]/v1"},
		{"text and a stray closing bracket", "http://[::1]extra]/v1"},
		{"repeated bracket group after a port", "http://[::1]:8080[::2]/v1"},
		{"userinfo with a repeated bracket group", "https://user:p%40ss@[::1][::2]/v1"},
		{"userinfo with text and a stray bracket", "https://user:p%40ss@[::1]extra]/v1"},
		{"userinfo with junk after the port", "https://user:p%40ss@[::1]:8443x/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "` + tc.upstream + `"}
			  ]
			}`
			// The request hits the valid first route only.
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
			for _, want := range []string{"route 2", `"admin"`, "upstream", "bracketed host", "IPv6"} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q", fail.Reason, want)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Errorf("an illegal bracketed host is a content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}

	// A valid literal with userinfo, a port, an encoded base path and an
	// encoded-slash query still resolves byte for byte through the boundary.
	config := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api",
	  "upstream":"https://user:p%40ss@[2001:DB8::1]:8443/v%2f"}]}`
	success := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"GET","target":"/api/x?q=%2f"}`))
	if success.RouteID != "api" {
		t.Errorf("routeId = %q, want api", success.RouteID)
	}
	if want := "https://user:p%40ss@[2001:DB8::1]:8443/v%2f/x?q=%2f"; success.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, want)
	}
}

func TestResolveCLIValidIPv6Upstreams(t *testing.T) {
	cases := []struct {
		name     string
		prefix   string
		upstream string
		target   string
		wantURL  string
	}{
		{
			name:     "compressed literal with userinfo, port and encoded path",
			prefix:   "/api",
			upstream: "https://user:p%40ss@[2001:db8::1]:8443/v%2f",
			target:   "/api/orders?a=1&a=",
			wantURL:  "https://user:p%40ss@[2001:db8::1]:8443/v%2f/orders?a=1&a=",
		},
		{
			name:     "encoded zone keeps its original spelling",
			prefix:   "/",
			upstream: "https://[fe80::1%25eth0]/base",
			target:   "/x",
			wantURL:  "https://[fe80::1%25eth0]/base/x",
		},
		{
			name:     "full form literal",
			prefix:   "/",
			upstream: "http://[2001:0db8:0000:0000:0000:0000:0000:0001]/b",
			target:   "/x",
			wantURL:  "http://[2001:0db8:0000:0000:0000:0000:0000:0001]/b/x",
		},
		{
			name:     "ipv4 tail and port",
			prefix:   "/",
			upstream: "http://[::ffff:192.168.0.1]:8080/b",
			target:   "/x",
			wantURL:  "http://[::ffff:192.168.0.1]:8080/b/x",
		},
		{
			name:     "ordinary domain is unaffected",
			prefix:   "/api",
			upstream: "http://api.internal/v1",
			target:   "/api/x?y=1",
			wantURL:  "http://api.internal/v1/x?y=1",
		},
		{
			name:     "bare ipv4 host without brackets is unaffected",
			prefix:   "/api",
			upstream: "http://127.0.0.1:8080/v1",
			target:   "/api/x",
			wantURL:  "http://127.0.0.1:8080/v1/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"` + tc.prefix +
				`","upstream":"` + tc.upstream + `"}]}`
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, config, request))
			if success.RouteID != "r" {
				t.Errorf("routeId = %q, want r", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.wantURL)
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
