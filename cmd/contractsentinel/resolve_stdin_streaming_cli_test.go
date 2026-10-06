package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These regression tests pin the distinction the resolve command must draw
// between "still waiting for the request on stdin" and "the configuration has
// already been rejected". They drive the command the way a real user does
// (config file argument, one JSON request on stdin, observable exit status /
// stdout / stderr), but stdin is an open pipe whose write side the test
// controls, so the request can be absent, partial, completed or never closed
// at all. Everything is local and offline; the upstreams never need to exist.

// streamingResolve is one resolve run whose stdin is a pipe the test feeds
// manually. The process is started eagerly; result() blocks for its exit.
type streamingResolve struct {
	cmd      *exec.Cmd
	stdin    *os.File // write end of the OS pipe handed to the child
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	finished chan struct{} // closed once Wait reaps the process
	err      error         // valid after finished closes
}

// startStreamingResolve writes config to a temp file and starts
// "resolve <config>" with an empty, still-open stdin pipe. Nothing is sent on
// stdin until the test writes it, and the pipe stays open until the test
// closes it. The pipe is a real OS pipe (an *os.File) rather than an io.Pipe:
// os/exec runs a copy goroutine for non-file stdin and makes Wait block on
// it, which would hide a child that exits on a bad config while the feed is
// still open. A file descriptor hands Wait back as soon as the process dies.
func startStreamingResolve(t *testing.T, config string) *streamingResolve {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "resolve", configPath)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdin = pr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start resolve helper: %v", err)
	}
	// The child has inherited the read end; the parent copy is unused.
	_ = pr.Close()

	s := &streamingResolve{
		cmd:      cmd,
		stdin:    pw,
		stdout:   &stdout,
		stderr:   &stderr,
		finished: make(chan struct{}),
	}
	go func() {
		s.err = cmd.Wait()
		close(s.finished)
	}()
	// If an assertion fails midway, make sure no fed-but-still-waiting child
	// or pipe write end outlives the test.
	t.Cleanup(func() {
		_ = pw.Close()
		select {
		case <-s.finished:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-s.finished
		}
	})
	return s
}

// assertStillWaiting fails if the resolve process has already exited while
// the named phase is in progress. finished is only closed by the reaper
// goroutine, so the check observes a real exit rather than racing the
// process.
func (s *streamingResolve) assertStillWaiting(t *testing.T, phase string) {
	t.Helper()
	select {
	case <-s.finished:
		t.Fatalf("resolve exited while %s: %v; it must keep waiting for stdin", phase, s.err)
	default:
	}
}

// write sends more request bytes without closing the pipe.
func (s *streamingResolve) write(t *testing.T, data string) {
	t.Helper()
	if _, err := io.WriteString(s.stdin, data); err != nil {
		t.Fatalf("feed stdin: %v", err)
	}
}

// finish closes stdin normally (EOF), then returns the observed result.
func (s *streamingResolve) finish(t *testing.T) resolveResult {
	t.Helper()
	if err := s.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	return s.result(t)
}

// abort releases the write side without delivering a request; used for
// cleanup after the process has already exited on its own. Closing an
// already-closed pipe returns an error, which is irrelevant for cleanup.
func (s *streamingResolve) abort() {
	_ = s.stdin.Close()
}

// result waits for the process to exit, failing if it takes longer than the
// deadline (a process stuck waiting for a request it should have rejected).
func (s *streamingResolve) result(t *testing.T) resolveResult {
	t.Helper()
	select {
	case <-s.finished:
		exitCode := 0
		if s.err != nil {
			var exitErr *exec.ExitError
			if errors.As(s.err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				t.Fatalf("run resolve helper: %v", s.err)
			}
		}
		return resolveResult{stdout: s.stdout.Bytes(), stderr: s.stderr.Bytes(), exitCode: exitCode}
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		s.abort()
		t.Fatalf("resolve did not exit within 5s; it is blocked on stdin instead of deciding")
		return resolveResult{}
	}
}

// assertInvalidConfig is the failure contract shared by the config cases:
// non-zero exit, completely empty stdout and exactly one JSON object on
// stderr carrying code invalid_config.
func assertInvalidConfig(t *testing.T, res resolveResult) struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
} {
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
	if fail.Reason == "" {
		t.Fatal("reason must be non-empty")
	}
	return fail
}

// TestResolveCLIInvalidConfigRejectedWhileStdinStaysOpen is the headline
// regression: with stdin open and carrying nothing (the requesting program
// may simply be slow), an invalid config must still be rejected immediately.
// The process exits on its own while the write side of the pipe is still
// held by the test, so it cannot be waiting for a request; the config error
// must neither be delayed until request failure nor masked as
// invalid_request. Broken config JSON is a parse failure that does not guess
// a route position; a later route's invalid rename rule is located by route
// position, id and 1-based rule index and is not misreported as bad JSON.
func TestResolveCLIInvalidConfigRejectedWhileStdinStaysOpen(t *testing.T) {
	// Route 2's second transform is a rename without "to". The request would
	// only ever hit route 1, which is perfectly usable.
	renameMissingToConfig := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://admin.internal",
	     "queryTransforms": [
	       {"op": "set", "name": "a", "value": "1"},
	       {"op": "rename", "name": "old"}
	     ]}
	  ]
	}`
	cases := []struct {
		name      string
		config    string
		want      []string
		forbidden []string
	}{
		{
			name:      "syntactically broken config JSON",
			config:    `{"routes":[ broken`,
			want:      []string{"not valid JSON"},
			forbidden: []string{"route ", "invalid_request"},
		},
		{
			name:   "second route rename rule missing to",
			config: renameMissingToConfig,
			want:   []string{"route 2", `"admin"`, "rule 2"},
			forbidden: []string{
				"not valid JSON", // a rule content error is not a syntax failure
				"invalid_request",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Stdin is opened but never written to and never closed: this is
			// exactly "input may be temporarily empty and still open".
			s := startStreamingResolve(t, tc.config)

			res := s.result(t)
			// The process exited without the pipe being closed; release the
			// write side now that the decision has been observed.
			s.abort()

			fail := assertInvalidConfig(t, res)
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

// TestResolveCLIWaitsForOpenStdinThenResolves pins the other half of the
// distinction for a *valid* config: the command must preserve its normal
// blocking behavior. While stdin is open but empty, and later while it holds
// only a prefix of the request JSON, the process must stay alive, emit
// nothing and report neither success nor invalid_request. Once the remaining
// bytes arrive and stdin closes, the complete request resolves normally with
// exit 0, empty stderr and the usual routeId / upstreamURL on stdout.
func TestResolveCLIWaitsForOpenStdinThenResolves(t *testing.T) {
	s := startStreamingResolve(t, cliSuccessConfig)

	// Phase 1: input is open but completely empty. The process must simply
	// wait rather than treating "no bytes yet" as an empty, invalid request.
	s.assertStillWaiting(t, "stdin was open but empty")
	time.Sleep(150 * time.Millisecond)
	s.assertStillWaiting(t, "stdin stayed open and empty")

	// Phase 2: only a fragment of the JSON has arrived. A truncated object
	// must not be parsed eagerly into an invalid_request or a success result.
	s.write(t, `{"method":"GET","tar`)
	time.Sleep(150 * time.Millisecond)
	s.assertStillWaiting(t, "stdin held only part of the request JSON")

	// Phase 3: the rest of the request arrives and the input ends. Normal
	// resolution must follow, honoring route selection, path joining and the
	// raw query bytes.
	s.write(t, `get":"/api/items?a=1&a=&x=%2f+&flag"}`)
	res := s.finish(t)

	success := assertResolveSuccess(t, res)
	if success.RouteID != "api" {
		t.Errorf("routeId = %q, want api", success.RouteID)
	}
	wantURL := "http://api.internal/v1/items?a=1&a=&x=%2f+&flag"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLIEndedInputWithoutValidRequestIsInvalidRequest covers what is
// allowed to be an error once stdin has actually ended: a completely empty
// request (distinct from "empty for now, still open") and a truncated JSON
// fragment closed before the object finishes both become invalid_request,
// with non-zero exit, empty stdout and one JSON error on stderr. The empty
// case is the same end state that phase 1 of the waiting test must NOT fail
// on while the pipe remains open.
func TestResolveCLIEndedInputWithoutValidRequestIsInvalidRequest(t *testing.T) {
	cases := []struct {
		name    string
		pending string
		feed    bool // whether pending is written before close
	}{
		{"closed with no request content at all", "", false},
		{"closed while the request JSON is incomplete", `{"method":"GET",`, true},
		{"closed after a complete but malformed request", `{not json`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := startStreamingResolve(t, cliSuccessConfig)
			if tc.feed {
				s.write(t, tc.pending)
			}
			// Give a valid config a moment in which it must simply wait; it
			// must not exit early while the pipe is open.
			time.Sleep(100 * time.Millisecond)
			s.assertStillWaiting(t, "stdin was still open")

			res := s.finish(t)
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
			if fail.Reason == "" {
				t.Fatal("reason must be non-empty")
			}
		})
	}
}
