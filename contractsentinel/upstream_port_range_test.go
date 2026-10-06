package contractsentinel

import (
	"strings"
	"testing"
)

// TestInvalidConfigUpstreamPortOutOfRange pins the TCP port range rule for
// the upstream address: an explicitly written, non-empty, all-digits port
// must be a decimal number from 0 to 65535, both ends included. 65536 or
// anything larger rejects the whole configuration as invalid_config, however
// the host is spelled — ordinary domain, bare IPv4 or bracketed IPv6 — and
// however long the digit string is: the value is decided on the decimal
// digits without any integer conversion, so no length can overflow into an
// accepted port, and leading zeros do not change the value ("00065536" is
// still out of range). The reason is a content error naming the route's
// 1-based position, its id and the upstream field and stating the 0–65535
// range, never a JSON syntax failure, and no config is handed back.
func TestInvalidConfigUpstreamPortOutOfRange(t *testing.T) {
	badUpstreams := []struct {
		name     string
		upstream string
	}{
		{"one past the maximum", "http://api.internal:65536/base"},
		{"far past the maximum", "http://api.internal:99999/base"},
		{"bracketed IPv6 host", "https://[::1]:99999/v1"},
		{"bracketed IPv6 with zone", "https://[fe80::1%25eth0]:65536/v1"},
		{"bare IPv4 host", "http://127.0.0.1:65536/base"},
		{"leading zeros do not rescue the value", "http://api.internal:00065536/base"},
		{"digit string too long to convert", "http://api.internal:99999999999999999999999999999999/base"},
		{"userinfo colon is not the port", "http://user:pass@api.internal:65536/base"},
		{"https without base path", "https://api.internal:65536"},
	}
	for _, tc := range badUpstreams {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
			  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"` + tc.upstream + `"}
			]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("expected invalid_config for upstream %q", tc.upstream)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "upstream", "port", "0 to 65535"} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("an out-of-range port is a content error, not a JSON syntax failure: %q", f.Reason)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
		})
	}

	// The offending route may be one the request never hits: the read still
	// fails up front instead of letting the first, valid route resolve.
	cfg, f := ParseConfig([]byte(`{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"http://api.internal:65536/base"}
	]}`))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("unhit route with an out-of-range port: got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}
}

// TestResolveUpstreamPortInRange pins the other half of the rule: ports from
// 0 to 65535 are legal on every host spelling, an absent port and the
// existing "host:" empty-port spelling stay accepted, and a legal port is
// carried into upstreamURL exactly as written — leading zeros included,
// never stripped or normalized. Numbers that are not the port (the userinfo
// after the colon, the IPv6 literal inside its brackets, digits in the base
// path) are never mistaken for one.
func TestResolveUpstreamPortInRange(t *testing.T) {
	good := []struct {
		name         string
		upstream     string
		wantUpstream string
	}{
		{"the maximum port", "http://api.internal:65535/base", "http://api.internal:65535/base/items"},
		{"port zero", "http://api.internal:0/base", "http://api.internal:0/base/items"},
		{"leading zeros are kept as written", "http://api.internal:00065535/base", "http://api.internal:00065535/base/items"},
		{"no port at all", "http://api.internal/base", "http://api.internal/base/items"},
		{"colon with an empty port", "http://api.internal:/base", "http://api.internal:/base/items"},
		{"bracketed IPv6 with port", "https://[::1]:8080/v1", "https://[::1]:8080/v1/items"},
		{"bracketed IPv6 without port", "http://[2001:db8::1]/v1", "http://[2001:db8::1]/v1/items"},
		{"userinfo colons are not ports", "http://user:pa:ss@api.internal:8080/base", "http://user:pa:ss@api.internal:8080/base/items"},
		{"userinfo digits are not a port", "http://user:99999@api.internal/base", "http://user:99999@api.internal/base/items"},
		{"digits in the base path are not a port", "http://api.internal/base/99999", "http://api.internal/base/99999/items"},
		{"big number in the base path", "http://api.internal:8080/65536", "http://api.internal:8080/65536/items"},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustConfig(t, `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"`+tc.upstream+`"}
			]}`)
			res, rf := Resolve(cfg, &Request{Method: "GET", Target: "/api/items"})
			if rf != nil {
				t.Fatalf("Resolve: %+v", rf)
			}
			if res.RouteID != "api" {
				t.Errorf("routeId = %q, want api", res.RouteID)
			}
			if res.UpstreamURL != tc.wantUpstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.wantUpstream)
			}
		})
	}
}

// TestInvalidConfigUpstreamPortRangePrecedence pins where the new check sits
// among the existing content errors: it runs in check layer 4 after the
// host-shape rules, so a missing host on the same route is still reported
// before its port, and the earliest route in the array still wins across
// routes.
func TestInvalidConfigUpstreamPortRangePrecedence(t *testing.T) {
	// A missing host on route 1 keeps its existing reason even though
	// route 2 carries an out-of-range port.
	_, f := ParseConfig([]byte(`{"routes":[
	  {"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"http://:8080/base"},
	  {"id":"b","methods":["GET"],"pathPrefix":"/b","upstream":"http://api.internal:65536/base"}
	]}`))
	if f == nil || !strings.Contains(f.Reason, "missing a host") {
		t.Fatalf("missing host must keep precedence over a later route's port: %+v", f)
	}

	// Of two out-of-range ports the earliest route in the array is reported.
	_, f = ParseConfig([]byte(`{"routes":[
	  {"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"http://a.internal:70000/base"},
	  {"id":"b","methods":["GET"],"pathPrefix":"/b","upstream":"http://b.internal:65536/base"}
	]}`))
	if f == nil || !strings.Contains(f.Reason, "route 1") || !strings.Contains(f.Reason, `"a"`) {
		t.Fatalf("the earliest route's port error must be reported: %+v", f)
	}
}
