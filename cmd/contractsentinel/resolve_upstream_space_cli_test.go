package main

import (
	"strings"
	"testing"
)

// These tests pin the upstream-base-path space rule at the command boundary:
// the resolve command reads and validates the whole configuration before it
// touches the request, so a direct ASCII space in any route's upstream base
// path fails the run as invalid_config even when the request itself is also
// invalid and would only have matched another, legal route.

// TestResolveCLIUpstreamBasePathSpaceRejectsConfig drives the failure
// contract: a spaced upstream base path on the second route rejects the read
// with non-zero exit, completely empty stdout and one JSON invalid_config
// object on stderr naming the route position, its id and the upstream field
// — a content error, never a JSON syntax failure. The request matches the
// first route only, and a variant whose request is itself invalid still
// reports the config error first.
func TestResolveCLIUpstreamBasePathSpaceRejectsConfig(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://api.internal/base path"}
	  ]
	}`
	want := []string{"route 2", `"admin"`, "upstream", "base path", "space"}
	forbidden := []string{"not valid JSON"}

	// The request would only hit the legal first route; the read still fails.
	assertCLIInvalidConfig(t, config, `{"method":"GET","target":"/api/items"}`, want, forbidden)

	// The same config alongside an invalid request (a direct space in the
	// target) still reports invalid_config: the config is processed first.
	assertCLIInvalidConfig(t, config, `{"method":"GET","target":"/api/a b"}`, want, forbidden)
}

// TestResolveCLIUpstreamBasePathEncodedSpaceResolves drives the success
// contract at the boundary: a percent-encoded "%20" in the upstream base
// path is legal path content, never decoded before the check, and reaches
// upstreamURL byte for byte together with the untouched raw query.
func TestResolveCLIUpstreamBasePathEncodedSpaceResolves(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/base%20path"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items?x=%2f&x="}`)
	hit := assertResolveSuccess(t, res)
	if hit.RouteID != "api" {
		t.Errorf("routeId = %q, want api", hit.RouteID)
	}
	if want := "http://api.internal/base%20path/items?x=%2f&x="; hit.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", hit.UpstreamURL, want)
	}
	if strings.Contains(hit.UpstreamURL, " ") {
		t.Errorf("upstreamURL must not contain a direct space: %q", hit.UpstreamURL)
	}
}
