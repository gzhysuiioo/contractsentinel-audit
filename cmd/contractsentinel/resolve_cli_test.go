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

func TestResolveCLIWrongFieldTypeNamesRouteAndField(t *testing.T) {
	// A GET /api request would hit the first route; the second route
	// ("orders") nonetheless makes the whole config invalid because its
	// methods value is a string instead of an array. The failure must point
	// at route 2, the orders id and the methods field, while remaining a
	// single JSON object on stderr with an empty stdout and non-zero exit.
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
	for _, want := range []string{"route 2", `"orders"`, "methods", "array"} {
		if !strings.Contains(fail.Reason, want) {
			t.Errorf("reason = %q, want substring %q (route position, id, field and expected type)",
				fail.Reason, want)
		}
	}

	// Once methods is a legal array the same (first-route) request resolves
	// successfully with matched route and upstream on stdout.
	fixedConfig := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "orders", "methods": ["GET", "POST"], "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	ok := runResolveCLI(t, fixedConfig, cliSuccessRequest)
	if ok.exitCode != 0 || len(ok.stderr) != 0 {
		t.Fatalf("exit=%d stderr=%q, want success", ok.exitCode, ok.stderr)
	}
	var success struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeOneJSON(t, ok.stdout, "stdout", &success)
	if success.RouteID != "api" || success.UpstreamURL != "http://api.internal/v1/items?a=1&a=&x=%2f+&flag" {
		t.Errorf("got %+v, want the hit route and joined upstream", success)
	}

	// A numeric entry inside an otherwise-array methods attribute the error
	// to that route's methods and identifies the offending entry.
	numEntry := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "orders", "methods": ["GET", 42], "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	entry := runResolveCLI(t, numEntry, cliSuccessRequest)
	if entry.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(entry.stdout) != 0 {
		t.Fatalf("stdout = %q, want empty", entry.stdout)
	}
	decodeOneJSON(t, entry.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Errorf("code = %q, want invalid_config", fail.Code)
	}
	for _, want := range []string{"route 2", `"orders"`, "methods", "entry 2", "string"} {
		if !strings.Contains(fail.Reason, want) {
			t.Errorf("reason = %q, want substring %q", fail.Reason, want)
		}
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
