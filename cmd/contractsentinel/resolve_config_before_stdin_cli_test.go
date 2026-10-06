package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests pin the ordering between config validation and reading stdin.
// An invalid but readable config must be rejected as soon as the config file
// is read: the command may not wait for EOF on stdin, so a caller that keeps
// the request pipe open (or whose pipe later fails) still sees invalid_config
// immediately, with stdout left empty. A valid config, by contrast, keeps
// waiting on an open pipe and must not read a moment without data as an empty
// request.
//
// The open-pipe tests hand the child an *os.File pipe rather than an io.Pipe:
// os/exec runs no stdin-copy goroutine for a plain file, so cmd.Wait returns
// the moment the child exits even though the request end is still open.

// runResolveCLIStdin is runResolveCLI with a caller-supplied stdin. It is
// only used when the supplied reader reaches EOF or fails on its own (an
// io.Pipe closed or closed-with-error); a reader that blocks forever would
// block cmd.Run past the child's exit and is exercised via startResolve.
func runResolveCLIStdin(t *testing.T, config string, stdin io.Reader) resolveResult {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "resolve", configPath)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdin = stdin
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

// runResolveCLIConfigPath spawns resolve against an arbitrary config path
// (used for a path that cannot be opened) with an open request pipe.
func runResolveCLIConfigPath(t *testing.T, configPath string) resolveResult {
	t.Helper()

	stdin, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create request pipe: %v", err)
	}
	defer stdin.Close()
	defer requestWrite.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "resolve", configPath)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("run resolve helper: %v", runErr)
		}
	}
	return resolveResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), exitCode: exitCode}
}

// startResolve starts the helper without waiting, wiring its stdin to an
// os.Pipe whose write end is returned. The child can be observed while the
// request end stays open: unlike an io.Reader pipe, an *os.File stdin starts
// no copy goroutine, so cleanup's Wait completes as soon as the child exits.
// If the child is meant to keep running, write the request and close the
// returned pipe before calling cleanup.
func startResolve(t *testing.T, config string) (*exec.Cmd, *os.File, func() resolveResult) {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	stdin, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create request pipe: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "resolve", configPath)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start resolve helper: %v", err)
	}
	stdin.Close() // the child now owns the read end

	done := make(chan resolveResult, 1)
	go func() {
		waitErr := cmd.Wait()
		requestWrite.Close()
		exitCode := 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
		}
		done <- resolveResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), exitCode: exitCode}
	}()

	cleanup := func() resolveResult {
		// Unblock a child that is still waiting on the open request pipe.
		_ = requestWrite.Close()
		select {
		case res := <-done:
			return res
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			res := <-done
			t.Fatalf("resolve did not exit; stdout=%q stderr=%q", res.stdout, res.stderr)
			return res
		}
	}
	return cmd, requestWrite, cleanup
}

// childRunning reports whether the helper process is still alive. Signal 0
// succeeds against the running child; an exited (or reaped) process gives
// ESRCH.
func childRunning(t *testing.T, cmd *exec.Cmd) bool {
	t.Helper()
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return false
		}
		t.Fatalf("probe child process: %v", err)
	}
	return true
}

// TestResolveCLIInvalidConfigRejectedWhileStdinOpen is the headline timing
// requirement: with the request write end held open and never closed, every
// config the existing validation already rejects must still make the command
// exit on its own with invalid_config, an empty stdout and the same reason it
// reports when stdin delivers a request. A command that waits for stdin EOF
// before parsing the config stays blocked and fails the liveness probe.
func TestResolveCLIInvalidConfigRejectedWhileStdinOpen(t *testing.T) {
	cases := []struct {
		name      string
		config    string
		want      []string
		forbidden []string
	}{
		{
			name:      "broken json syntax",
			config:    `{"routes":[ broken`,
			want:      []string{"not valid JSON"},
			forbidden: []string{"route "},
		},
		{
			name: "wrong field type on a later route the request cannot hit",
			config: `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "orders", "methods": "GET", "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
			  ]
			}`,
			want:      []string{"route 2", `"orders"`, "methods must be an array"},
			forbidden: []string{"not valid JSON"},
		},
		{
			name: "illegal query transform rule on an unreachable route",
			config: `{
			  "routes": [
			    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://admin.internal",
			     "queryTransforms": [
			       {"op": "set", "name": "a", "value": "1"},
			       {"op": "delete", "name": "x"}
			     ]}
			  ]
			}`,
			want:      []string{"route 2", `"admin"`, "rule 2"},
			forbidden: []string{"not valid JSON"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, requestWrite, cleanup := startResolve(t, tc.config)
			defer requestWrite.Close()

			// Wait briefly without closing the request end: the child must
			// reject the config and exit while stdin is still open.
			deadline := time.Now().Add(2 * time.Second)
			for childRunning(t, cmd) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if childRunning(t, cmd) {
				cleanup()
				t.Fatal("resolve kept waiting on stdin EOF instead of rejecting the invalid config")
			}

			res := cleanup()
			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero while stdin stays open")
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
}

// TestResolveCLIInvalidConfigBeatsFailingStdin pairs an invalid config with a
// request pipe that fails before delivering anything: the config is already
// known invalid, so its failure must still be invalid_config rather than an
// invalid_request read error.
func TestResolveCLIInvalidConfigBeatsFailingStdin(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		_ = pw.CloseWithError(errors.New("simulated upstream writer crash"))
	}()

	res := runResolveCLIStdin(t, `{"routes":[ broken`, pr)

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
		t.Fatalf("code = %q, want invalid_config even when stdin fails first", fail.Code)
	}
	if !strings.Contains(fail.Reason, "not valid JSON") {
		t.Fatalf("reason = %q, want the config syntax failure", fail.Reason)
	}
}

// TestResolveCLIValidConfigWaitsForOpenStdin proves the wait is unchanged for
// a usable config: while the pipe is open but empty the child must stay
// running rather than treating the absence of data as an empty request, then
// resolve normally once one complete JSON request is delivered and the pipe
// closes.
func TestResolveCLIValidConfigWaitsForOpenStdin(t *testing.T) {
	cmd, requestWrite, cleanup := startResolve(t, cliSuccessConfig)

	// Give the child time to start; it must be blocked reading the request,
	// neither exited nor reporting an empty-request failure.
	time.Sleep(300 * time.Millisecond)
	if !childRunning(t, cmd) {
		res := cleanup()
		t.Fatalf("resolve exited before any request arrived: exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}

	if _, err := io.WriteString(requestWrite, cliSuccessRequest); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := requestWrite.Close(); err != nil {
		t.Fatalf("close request pipe: %v", err)
	}

	success := assertResolveSuccess(t, cleanup())
	if success.RouteID != "api" {
		t.Errorf("routeId = %q, want api", success.RouteID)
	}
	if want := "http://api.internal/v1/items?a=1&a=&x=%2f+&flag"; success.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, want)
	}
}

// TestResolveCLIValidConfigFailingStdinIsInvalidRequest keeps the existing
// read-failure behavior for a valid config: when the stdin descriptor itself
// fails before the request arrives (here stdin is a directory, whose read(2)
// fails with EISDIR on Linux), the result is invalid_request naming the read
// failure, never an invalid_config or a silent success.
func TestResolveCLIValidConfigFailingStdinIsInvalidRequest(t *testing.T) {
	// An *os.File is handed to the child as descriptor 0 directly, so the
	// failure happens inside the child's own read rather than in a parent
	// copy goroutine (which would only look like EOF to the child).
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open stdin directory: %v", err)
	}
	defer dir.Close()

	res := runResolveCLIStdin(t, cliSuccessConfig, dir)

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
	if !strings.Contains(fail.Reason, "cannot read request from stdin") {
		t.Fatalf("reason = %q, want the stdin read failure", fail.Reason)
	}
}

// TestResolveCLIUnreadableConfigStillInvalidConfig keeps the existing
// file-read failure: a config path that cannot be opened yields
// invalid_config with the read reason even though the request pipe never
// delivers anything.
func TestResolveCLIUnreadableConfigStillInvalidConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	res := runResolveCLIConfigPath(t, missing)

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
	for _, want := range []string{"cannot read config file", "does-not-exist.json"} {
		if !strings.Contains(fail.Reason, want) {
			t.Errorf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
}
