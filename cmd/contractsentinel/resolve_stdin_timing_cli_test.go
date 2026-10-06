package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests pin the timing contract of resolve at the real command entry:
// the configuration is judged before the request is awaited. A config the
// rules can prove invalid must fail immediately — even while the requesting
// program still holds the stdin pipe open and has sent nothing — instead of
// blocking on a request that may never arrive or surfacing later as
// invalid_request. A valid config, on the other hand, must keep waiting: a
// temporarily empty pipe or a half-delivered JSON request is neither a
// success nor an invalid_request, and only the completed request followed by
// EOF produces a result. Everything runs offline; the upstreams are never
// contacted.

// resolveCLIProcess is one spawned resolve command whose stdin is a pipe the
// test controls, so the test decides when (and whether) request bytes arrive
// and when EOF happens.
type resolveCLIProcess struct {
	cmd    *exec.Cmd
	stdin  *os.File // write end; the child reads from the other end
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	done   chan error

	finished bool
	waitErr  error
}

// startResolveCLI writes config to a temp file and spawns the helper binary
// with "resolve <config>", leaving stdin open with no bytes sent yet.
func startResolveCLI(t *testing.T, config string) *resolveCLIProcess {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "resolve", configPath)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	cmd.Stdin = stdinR
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		stdinR.Close()
		stdinW.Close()
		t.Fatalf("start resolve helper: %v", err)
	}
	// The child holds its own copy of the read end; the parent only writes.
	stdinR.Close()

	p := &resolveCLIProcess{
		cmd:    cmd,
		stdin:  stdinW,
		stdout: stdout,
		stderr: stderr,
		done:   make(chan error, 1),
	}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		p.stdin.Close()
		if !p.poll() {
			cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

// poll records the exit result if the command has finished and reports
// whether it has.
func (p *resolveCLIProcess) poll() bool {
	if p.finished {
		return true
	}
	select {
	case p.waitErr = <-p.done:
		p.finished = true
	default:
	}
	return p.finished
}

// awaitExit requires the command to finish within timeout and returns what
// the parent can observe. A command that is still blocked (for example
// waiting on a request it should not be waiting for) fails the test.
func (p *resolveCLIProcess) awaitExit(t *testing.T, timeout time.Duration, what string) resolveResult {
	t.Helper()
	if !p.poll() {
		select {
		case p.waitErr = <-p.done:
			p.finished = true
		case <-time.After(timeout):
			t.Fatalf("%s: command did not exit within %s while stdin was still open; it must not wait for a request", what, timeout)
		}
	}
	return p.result()
}

// assertStillWaiting requires the command to remain running for the whole
// grace period: exiting early — with a success or an invalid_request — while
// the request is still incomplete fails the test.
func (p *resolveCLIProcess) assertStillWaiting(t *testing.T, grace time.Duration, what string) {
	t.Helper()
	time.Sleep(grace)
	if p.poll() {
		res := p.result()
		t.Fatalf("%s: command exited while the request was still incomplete (exit %d, stdout %q, stderr %q); want it to keep waiting for stdin",
			what, res.exitCode, res.stdout, res.stderr)
	}
}

// result converts the recorded wait error into the observable exit code.
func (p *resolveCLIProcess) result() resolveResult {
	exitCode := 0
	if p.waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(p.waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return resolveResult{stdout: p.stdout.Bytes(), stderr: p.stderr.Bytes(), exitCode: exitCode}
}

// write sends more request bytes without closing the pipe.
func (p *resolveCLIProcess) write(t *testing.T, data string) {
	t.Helper()
	if _, err := p.stdin.Write([]byte(data)); err != nil {
		t.Fatalf("write request bytes to stdin: %v", err)
	}
}

// endRequest closes the pipe, delivering EOF after whatever was written.
func (p *resolveCLIProcess) endRequest(t *testing.T) {
	t.Helper()
	if err := p.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
}

// assertCLIInvalidConfigFailure checks the shared failure contract for a
// config rejection: non-zero exit, completely empty stdout and exactly one
// JSON invalid_config object on stderr whose reason contains every want
// substring and none of forbidden.
func assertCLIInvalidConfigFailure(t *testing.T, res resolveResult, want, forbidden []string) {
	t.Helper()
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
	for _, sub := range want {
		if !strings.Contains(fail.Reason, sub) {
			t.Errorf("reason = %q, want substring %q", fail.Reason, sub)
		}
	}
	for _, sub := range forbidden {
		if strings.Contains(fail.Reason, sub) {
			t.Errorf("reason = %q must not contain %q", fail.Reason, sub)
		}
	}
}

// TestResolveCLIBrokenConfigJSONFailsBeforeStdinEOF proves a syntactically
// broken config is rejected the moment it is read: the command exits non-zero
// on its own while the requesting program still holds stdin open and has sent
// nothing, stdout stays completely empty, and stderr carries exactly one JSON
// error with code invalid_config whose reason says the config JSON could not
// be parsed without guessing a route or rule position.
func TestResolveCLIBrokenConfigJSONFailsBeforeStdinEOF(t *testing.T) {
	p := startResolveCLI(t, `{"routes":[ broken`)

	res := p.awaitExit(t, 10*time.Second, "broken config JSON")
	assertCLIInvalidConfigFailure(t, res,
		[]string{"not valid JSON"},
		[]string{"route 1", "route 2", "queryTransforms rule", "invalid_request"})
}

// TestResolveCLIInvalidRenameRuleFailsBeforeStdinEOF proves a structurally
// invalid rule on a later route rejects the whole configuration before any
// request is awaited: route 1 would answer every request, but route 2's
// second queryTransforms rule is a rename without "to", so the command exits
// non-zero while stdin is still open. The reason keeps the 1-based route
// position, the route id and the 1-based rule index, and must not mislabel
// the rule error as broken config JSON.
func TestResolveCLIInvalidRenameRuleFailsBeforeStdinEOF(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "hit", "methods": ["*"], "pathPrefix": "/",
	     "upstream": "http://hit.internal"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin",
	     "upstream": "http://admin.internal",
	     "queryTransforms": [
	       {"op": "set", "name": "a", "value": "1"},
	       {"op": "rename", "name": "old"}
	     ]}
	  ]
	}`
	p := startResolveCLI(t, config)

	res := p.awaitExit(t, 10*time.Second, "invalid rename rule")
	assertCLIInvalidConfigFailure(t, res,
		[]string{"route 2", `"admin"`, "rule 2"},
		[]string{"not valid JSON", "invalid_request"})
}

// TestResolveCLIValidConfigWaitsForCompleteRequest proves a valid config
// keeps the command waiting on stdin: a temporarily empty pipe and a
// half-delivered JSON request produce neither a success nor an
// invalid_request. Once the rest of the request arrives and stdin closes,
// the command resolves it by the usual rules — matched routeId, joined
// upstreamURL — with empty stderr.
func TestResolveCLIValidConfigWaitsForCompleteRequest(t *testing.T) {
	p := startResolveCLI(t, cliSuccessConfig)

	// Nothing sent yet and the pipe still open: not an empty request.
	p.assertStillWaiting(t, 300*time.Millisecond, "temporarily empty stdin")

	// Only part of the JSON document delivered: not an invalid request.
	p.write(t, `{"method":"GET","target":"/api/it`)
	p.assertStillWaiting(t, 300*time.Millisecond, "partial request JSON")

	// The remainder plus EOF completes the request; it resolves normally.
	p.write(t, `ems?a=1&a=&flag"}`)
	p.endRequest(t)
	res := p.awaitExit(t, 10*time.Second, "completed request")
	success := assertResolveSuccess(t, res)
	if success.RouteID != "api" {
		t.Errorf("routeId = %q, want api", success.RouteID)
	}
	if want := "http://api.internal/v1/items?a=1&a=&flag"; success.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, want)
	}
}

// TestResolveCLIEndedInputRequestErrors pins the other side of the timing
// contract: once stdin has ended, whatever arrived is the whole request. A
// closed pipe carrying broken JSON is invalid_request, and a closed pipe that
// delivered nothing at all is invalid_request too — both unlike a
// temporarily empty pipe that is still open. Each failure exits non-zero,
// leaves stdout completely empty and emits one JSON error on stderr.
func TestResolveCLIEndedInputRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		send string
	}{
		{"broken JSON before EOF", `{not json`},
		{"no bytes at all before EOF", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := startResolveCLI(t, cliSuccessConfig)
			if tc.send != "" {
				p.write(t, tc.send)
			}
			p.endRequest(t)

			res := p.awaitExit(t, 10*time.Second, "ended input")
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
			if fail.Reason == "" {
				t.Error("reason must be non-empty")
			}
		})
	}
}
