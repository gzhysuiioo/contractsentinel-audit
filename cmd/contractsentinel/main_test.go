package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// resolveBinaryPath is the binary built once in TestMain so every scenario
// exercises the real command entry point: config file argument plus one JSON
// request on stdin, exactly as a user would invoke it.
var resolveBinaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "contractsentinel-cli")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binary := filepath.Join(dir, "contractsentinel")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("cannot build contractsentinel test binary: " + err.Error() + "\n" + string(out))
	}
	resolveBinaryPath = binary

	os.Exit(m.Run())
}

// cliResult is the observable outcome of one resolve invocation.
type cliResult struct {
	stdout   string
	stderr   string
	exitCode int
}

// runResolve writes config to a temp file, feeds requestJSON on stdin and
// returns the captured streams and exit code; nothing touches the network.
func runResolveCLI(t *testing.T, config, requestJSON string) cliResult {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(resolveBinaryPath, "resolve", configPath)
	cmd.Stdin = strings.NewReader(requestJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run resolve: %v", err)
		}
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCode}
}

// decodeSingleJSON decodes exactly one JSON value from s and fails if it is
// followed by another JSON token or any non-whitespace content.
func decodeSingleJSON(t *testing.T, s, stream string, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s is not a single JSON value: %v (raw %q)", stream, err, s)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("%s carries more than one JSON value (extra %v): %q", stream, extra, s)
	}
}

func TestCLIResolveSuccess(t *testing.T) {
	config := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"}
	]}`
	request := `{"method":"GET","target":"/api/items?a=1&a=&x=%2f+&flag"}`

	res := runResolveCLI(t, config, request)
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", res.exitCode, res.stderr)
	}
	if res.stderr != "" {
		t.Fatalf("stderr = %q, want empty", res.stderr)
	}

	// One JSON object on stdout, nothing before or after it apart from the
	// encoder's trailing newline.
	wantLine := `{"routeId":"api","upstreamURL":"http://api.internal/v1/items?a=1&a=&x=%2f+&flag"}`
	if res.stdout != wantLine+"\n" {
		t.Fatalf("stdout = %q, want %q", res.stdout, wantLine+"\n")
	}
	if !strings.Contains(res.stdout, "&") {
		t.Fatalf("ampersands must appear literally rather than as a unicode escape, stdout = %q", res.stdout)
	}
	// Built by concatenation so the Go source itself never contains a
	// & escape that an editor or decoder could misread.
	unicodeEscapedAmp := "\\" + "u0026"
	if strings.Contains(res.stdout, unicodeEscapedAmp) {
		t.Fatalf("ampersands must not be unicode-escaped, stdout = %q", res.stdout)
	}
	for _, noise := range []string{"usage", "demo", "debug", "audit"} {
		if strings.Contains(res.stdout, noise) {
			t.Fatalf("stdout must not contain %q text: %q", noise, res.stdout)
		}
	}

	var got struct {
		RouteID     string `json:"routeId"`
		UpstreamURL string `json:"upstreamURL"`
	}
	decodeSingleJSON(t, res.stdout, "stdout", &got)
	if got.RouteID != "api" {
		t.Errorf("routeId = %q, want api", got.RouteID)
	}
	if got.UpstreamURL != "http://api.internal/v1/items?a=1&a=&x=%2f+&flag" {
		t.Errorf("upstreamURL = %q, want the raw query bytes preserved", got.UpstreamURL)
	}
}

func TestCLIResolveRejectsInvalidConfigOnUnhitRoute(t *testing.T) {
	// A GET /api/items request would hit the first route, but the second
	// route's second query rule uses the unsupported "delete" op. The whole
	// config must be refused even though that route never matches.
	config := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"other","methods":["GET"],"pathPrefix":"/other","upstream":"http://other.internal","queryTransforms":[
	    {"op":"set","name":"a","value":"1"},
	    {"op":"delete","name":"a"}
	  ]}
	]}`
	request := `{"method":"GET","target":"/api/items?z=1"}`

	res := runResolveCLI(t, config, request)
	if res.exitCode == 0 {
		t.Fatal("expected non-zero exit for invalid_config")
	}
	if res.stdout != "" {
		t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
	}

	var failure struct {
		Code       string   `json:"code"`
		Reason     string   `json:"reason"`
		Candidates []string `json:"candidates"`
	}
	decodeSingleJSON(t, res.stderr, "stderr", &failure)
	if failure.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", failure.Code)
	}
	if strings.TrimSpace(failure.Reason) == "" {
		t.Fatal("reason must be non-empty")
	}
	for _, want := range []string{"route 2", `"other"`, "rule 2", "delete"} {
		if !strings.Contains(failure.Reason, want) {
			t.Fatalf("reason = %q, want it to locate %s", failure.Reason, want)
		}
	}
}

func TestCLIResolveConflictSamePrefixExcludesWildcard(t *testing.T) {
	// Two concrete GET routes share the same prefix, with no longer prefix
	// to win; a same-prefix wildcard route exists but must not be a candidate.
	config := `{"routes":[
	  {"id":"zeta","methods":["GET"],"pathPrefix":"/same","upstream":"http://z.internal"},
	  {"id":"alpha","methods":["GET"],"pathPrefix":"/same","upstream":"http://a.internal"},
	  {"id":"wide","methods":["*"],"pathPrefix":"/same","upstream":"http://w.internal"}
	]}`
	request := `{"method":"GET","target":"/same/items"}`

	res := runResolveCLI(t, config, request)
	if res.exitCode == 0 {
		t.Fatal("expected non-zero exit for route_conflict")
	}
	if res.stdout != "" {
		t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
	}

	var failure struct {
		Code       string   `json:"code"`
		Reason     string   `json:"reason"`
		Candidates []string `json:"candidates"`
	}
	decodeSingleJSON(t, res.stderr, "stderr", &failure)
	if failure.Code != "route_conflict" {
		t.Fatalf("code = %q, want route_conflict", failure.Code)
	}
	if strings.TrimSpace(failure.Reason) == "" {
		t.Fatal("reason must be non-empty")
	}
	wantCandidates := []string{"alpha", "zeta"}
	if len(failure.Candidates) != len(wantCandidates) {
		t.Fatalf("candidates = %v, want exactly %v (wildcard excluded)", failure.Candidates, wantCandidates)
	}
	for i := range wantCandidates {
		if failure.Candidates[i] != wantCandidates[i] {
			t.Fatalf("candidates = %v, want lexicographically sorted %v", failure.Candidates, wantCandidates)
		}
	}
}
