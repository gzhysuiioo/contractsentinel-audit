package main

import (
	"testing"
)

// These tests pin the upstream port range rule at the command boundary: the
// resolve command reads and validates the whole configuration before it
// touches the request, so an out-of-range port on any route fails the run as
// invalid_config even when the request would only have matched another,
// legal route.

// TestResolveCLIUpstreamPortOutOfRangeRejectsConfig drives the failure
// contract: an explicitly written port past 65535 on the second route
// rejects the read with non-zero exit, completely empty stdout and one JSON
// invalid_config object on stderr naming the route position, its id and the
// upstream field and stating the 0–65535 range — a content error, never a
// JSON syntax failure. The request matches the first route only.
func TestResolveCLIUpstreamPortOutOfRangeRejectsConfig(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "http://api.internal:65536/base"}
	  ]
	}`
	want := []string{"route 2", `"admin"`, "upstream", "port", "0 to 65535"}
	forbidden := []string{"not valid JSON"}

	// The request would only hit the legal first route; the read still fails.
	assertCLIInvalidConfig(t, config, `{"method":"GET","target":"/api/items"}`, want, forbidden)

	// A bracketed IPv6 host answers to the same range.
	configV6 := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
	    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin", "upstream": "https://[::1]:99999/v1"}
	  ]
	}`
	assertCLIInvalidConfig(t, configV6, `{"method":"GET","target":"/api/items"}`, want, forbidden)
}

// TestResolveCLIUpstreamPortInRangeResolves drives the success contract at
// the boundary: a legal port reaches upstreamURL exactly as written —
// leading zeros included — and the route selection, path joining and raw
// query string are unchanged.
func TestResolveCLIUpstreamPortInRangeResolves(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal:00065535/v1"}
	  ]
	}`
	res := runResolveCLI(t, config, `{"method":"GET","target":"/api/items?x=%2f&x="}`)
	hit := assertResolveSuccess(t, res)
	if hit.RouteID != "api" {
		t.Errorf("routeId = %q, want api", hit.RouteID)
	}
	if want := "http://api.internal:00065535/v1/items?x=%2f&x="; hit.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", hit.UpstreamURL, want)
	}
}
