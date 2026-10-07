package main

import (
	"strings"
	"testing"
)

// These tests pin the upstream userinfo redaction at the command boundary:
// when a config error reason quotes an upstream address that carries
// credentials, the resolve command's stderr JSON shows the address with the
// whole userinfo segment replaced by "***" (the '@' kept), so saving the
// diagnostic cannot persist the password. The run still exits non-zero with
// completely empty stdout and the invalid_config code, and a legal upstream
// with userinfo still resolves with the original address in upstreamURL.

// TestResolveCLIUpstreamUserinfoRedactedOnFailure drives the failure
// contract: an upstream whose credentials precede a missing host is
// rejected, and the stderr reason shows "https://***@:8443/v1" — never the
// username, never the password, encoded or decoded — while still naming the
// route position, its id, the upstream field and the actual problem.
func TestResolveCLIUpstreamUserinfoRedactedOnFailure(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "https://alice:s3cr%40t@:8443/v1"}
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
	for _, want := range []string{"route 2", `"admin"`, "upstream", "missing a host", `"https://***@:8443/v1"`} {
		if !strings.Contains(fail.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, want)
		}
	}
	for _, leaked := range []string{"alice", "s3cr%40t", "s3cr@t"} {
		if strings.Contains(fail.Reason, leaked) {
			t.Fatalf("reason = %q leaks userinfo %q", fail.Reason, leaked)
		}
	}
}

// TestResolveCLIUpstreamUserinfoPreservedOnSuccess drives the success
// contract: redaction only touches failure diagnostics, so a legal upstream
// with userinfo resolves with the original address — credentials and
// percent escapes included — in upstreamURL.
func TestResolveCLIUpstreamUserinfoPreservedOnSuccess(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "https://alice:s3cr%40t@host.internal:8443/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items"}`)
	hit := assertResolveSuccess(t, res)
	if hit.RouteID != "api" {
		t.Errorf("routeId = %q, want api", hit.RouteID)
	}
	if want := "https://alice:s3cr%40t@host.internal:8443/v1/items"; hit.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", hit.UpstreamURL, want)
	}
}
