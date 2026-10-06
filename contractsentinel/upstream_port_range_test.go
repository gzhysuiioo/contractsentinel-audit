package contractsentinel

import (
	"strings"
	"testing"
)

// These tests pin the upstream port-range rule: an explicitly written numeric
// port is a TCP port number judged by its decimal value and must be in the
// range 0–65535 inclusive. The check runs on the raw splitUpstream boundaries
// in check layer 4 (Config.validate), so it applies equally to an ordinary
// domain, a bare IPv4 host and a bracketed IPv6 host; a colon in userinfo,
// inside an IPv6 literal or in the base path, and digits in the base path, can
// never be mistaken for a port. This is an address-content error in legal
// JSON: every rejection is invalid_config, names the upstream field, the
// route's 1-based position and its id and states the 0–65535 range, never a
// JSON syntax failure.

// parseUpstream wraps one route around an upstream and runs ParseConfig.
func parseUpstream(t *testing.T, upstream string) (*Config, *Failure) {
	t.Helper()
	src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"` + upstream + `"}]}`
	return ParseConfig([]byte(src))
}

// TestInvalidConfigUpstreamPortOutOfRange drives the headline rejections:
// 65536, 99999 and a digit string far beyond an integer's width must be
// refused for a domain, an IPv4 host and a bracketed IPv6 host alike, and
// leading zeros change the value but not the decision (00065536 is still
// 65536). A long digit string must not be accepted because an integer
// conversion overflows.
func TestInvalidConfigUpstreamPortOutOfRange(t *testing.T) {
	// A number with many more digits than fit an int or int64. Its value is
	// unambiguously over 65535 regardless of platform width.
	const huge = "99999999999999999999999999999999999999999999999999"
	badUpstreams := []struct {
		name     string
		upstream string
		port     string
	}{
		{"domain port one above the maximum", "http://api.internal:65536/base", "65536"},
		{"domain five digit over range without a base path", "http://api.internal:99999", "99999"},
		{"domain huge port", "http://api.internal:" + huge + "/base", huge},
		{"ipv4 port one above the maximum", "http://192.0.2.1:65536/base", "65536"},
		{"ipv4 huge port without a base path", "http://192.0.2.1:" + huge, huge},
		{"bracketed ipv6 headline address", "https://[::1]:99999/v1", "99999"},
		{"bracketed ipv6 one above the maximum", "http://[2001:db8::1]:65536/base", "65536"},
		{"bracketed ipv6 huge port", "https://[fe80::1]:" + huge, huge},
		{"domain port with leading zeros still over range", "http://api.internal:00065536/base", "00065536"},
		{"bracketed ipv6 port with leading zeros still over range", "http://[::1]:00099999", "00099999"},
		{"https domain one above maximum", "https://api.internal:65536", "65536"},
		{"port over range after userinfo", "https://user:p%40ss@api.internal:65536/v1", "65536"},
	}
	for _, tc := range badUpstreams {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := parseUpstream(t, tc.upstream)
			if f == nil {
				t.Fatalf("expected invalid_config for upstream %q, it was accepted", tc.upstream)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			for _, want := range []string{"route 1", `"r"`, "upstream", tc.port, "0-65535"} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, forbidden := range []string{"not valid JSON", "invalid port"} {
				if strings.Contains(f.Reason, forbidden) {
					t.Fatalf("an out-of-range numeric port is an address-content range error, not %q: %q",
						forbidden, f.Reason)
				}
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
		})
	}
}

// TestUpstreamPortInRangeStillAccepted drives the accepted side: 0, 65535 and
// every smaller value pass, leading zeros keep the same value and — crucially
// — keep their original spelling when the address is joined, no port and a
// trailing colon (empty port) stay legal, and the legal ports work on domains,
// IPv4 hosts and bracketed IPv6 hosts.
func TestUpstreamPortInRangeStillAccepted(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		target   string
		want     string
	}{
		{"domain port zero", "http://api.internal:0/base", "/x", "http://api.internal:0/base/x"},
		{"domain maximum port", "http://api.internal:65535/base", "/x", "http://api.internal:65535/base/x"},
		{"domain maximum with leading zeros is kept verbatim", "http://api.internal:00065535/base", "/x",
			"http://api.internal:00065535/base/x"},
		{"domain zero with leading zeros is kept verbatim", "http://api.internal:00000/base", "/x",
			"http://api.internal:00000/base/x"},
		{"domain ordinary port", "http://api.internal:8080/base", "/x", "http://api.internal:8080/base/x"},
		{"ipv4 maximum port", "http://192.0.2.1:65535/base", "/x", "http://192.0.2.1:65535/base/x"},
		{"ipv4 leading-zero maximum is kept verbatim", "http://192.0.2.1:000080/base", "/x",
			"http://192.0.2.1:000080/base/x"},
		{"bracketed ipv6 maximum port", "http://[::1]:65535/v1", "/x", "http://[::1]:65535/v1/x"},
		{"bracketed ipv6 leading-zero maximum is kept verbatim", "https://[::1]:00065535/v1", "/x",
			"https://[::1]:00065535/v1/x"},
		{"bracketed ipv6 port zero", "https://[2001:db8::1]:0/b", "/x", "https://[2001:db8::1]:0/b/x"},
		{"domain no port is untouched", "http://api.internal/base", "/x", "http://api.internal/base/x"},
		{"domain trailing colon is an empty port and stays legal", "http://api.internal:/base", "/x",
			"http://api.internal:/base/x"},
		{"bracketed ipv6 trailing colon is an empty port and stays legal", "http://[::1]:/v1", "/x",
			"http://[::1]:/v1/x"},
		{"maximum port after userinfo is kept verbatim", "https://user:pa:ss@api.internal:65535/b", "/x",
			"https://user:pa:ss@api.internal:65535/b/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustConfig(t, `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"`+
				tc.upstream+`"}]}`)
			res := resolveJSON(t, cfg, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != "r" {
				t.Errorf("routeId = %q, want r", res.RouteID)
			}
			if res.UpstreamURL != tc.want {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.want)
			}
		})
	}
}

// TestUpstreamPortRangeOnlyReadsTheRealPort pins the boundary discipline: the
// rule reads only the host's port slot via splitUpstream, so colons and digit
// runs that belong to userinfo, an IPv6 address or the base path must never be
// judged as a port. Each address is legal and resolves byte for byte.
func TestUpstreamPortRangeOnlyReadsTheRealPort(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		target   string
		want     string
	}{
		// Digits over 65535 appear only in the base path, which is not a port.
		{"large number in the base path is not a port", "http://api.internal/base/65536", "/x",
			"http://api.internal/base/65536/x"},
		// Userinfo carries the over-range-looking number; the host has no port.
		{"colon and large number in userinfo are not a port", "http://user:65536@api.internal/base", "/x",
			"http://user:65536@api.internal/base/x"},
		// The IPv6 groups contain port-like numeric hextets; only the
		// bracketed host exists and there is no port at all.
		{"numeric hextets inside brackets are not a port", "http://[2001:db8::1:8443]/base", "/x",
			"http://[2001:db8::1:8443]/base/x"},
		// Address-internal colons with a separate, in-range real port.
		{"ipv6 groups with an in range port", "http://[2001:db8::1]:8443/base", "/x",
			"http://[2001:db8::1]:8443/base/x"},
		// A colon in the base path plus a numeric but in-range host port.
		{"colon in base path and in range host port", "http://api.internal:8080/a:65536", "/x",
			"http://api.internal:8080/a:65536/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustConfig(t, `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"`+
				tc.upstream+`"}]}`)
			res := resolveJSON(t, cfg, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != "r" {
				t.Errorf("routeId = %q, want r", res.RouteID)
			}
			if res.UpstreamURL != tc.want {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.want)
			}
		})
	}

	// The mirror case: a port-looking hextet inside an IPv6 host does not
	// rescue an actually over-range port after the closing bracket.
	cfg, f := parseUpstream(t, "http://[2001:db8::1:8443]:65536/base")
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config for the real port", cfg, f)
	}
	for _, want := range []string{"route 1", `"r"`, "upstream", "65536", "0-65535"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
}

// TestUpstreamPortRangeNonNumericTextKeepsItsMeaning pins that the range rule
// judges only numeric values: illegal non-numeric port text keeps the existing
// url.Parse rejection rather than being renamed an out-of-range port.
func TestUpstreamPortRangeNonNumericTextKeepsItsMeaning(t *testing.T) {
	for _, upstream := range []string{
		"http://api.internal:abc/base",
		"http://api.internal:80abc/base",
		"http://api.internal:abcdef/base",
	} {
		cfg, f := parseUpstream(t, upstream)
		if f == nil {
			t.Fatalf("expected rejection for upstream %q", upstream)
		}
		if f.Code != "invalid_config" {
			t.Fatalf("code = %q, want invalid_config", f.Code)
		}
		if !strings.Contains(f.Reason, "invalid port") {
			t.Fatalf("non-numeric port %q must keep the url.Parse invalid-port reason, got %q",
				upstream, f.Reason)
		}
		if strings.Contains(f.Reason, "0-65535") {
			t.Fatalf("non-numeric port %q must not be called an out-of-range number: %q", upstream, f.Reason)
		}
		if cfg != nil {
			t.Fatalf("a rejected config must not be returned")
		}
	}
}

// TestUpstreamPortOutOfRangeRejectsWholeConfig proves the rule fails the whole
// document while it is read, even when the current request would only hit a
// different, legal route: ParseConfig hands back no config at all.
func TestUpstreamPortOutOfRangeRejectsWholeConfig(t *testing.T) {
	src := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"http://api.internal:65536/base"}
	]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	for _, want := range []string{"route 2", `"admin"`, "upstream", "65536", "0-65535"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	if strings.Contains(f.Reason, "not valid JSON") {
		t.Fatalf("an out-of-range port is a content error, not a JSON syntax failure: %q", f.Reason)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, so /api cannot resolve either")
	}

	// Within layer 4 the earliest route in the array wins: an over-range port
	// on route 1 is reported before a different content error on route 2.
	earlier := `{"routes":[
	  {"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"http://h:99999"},
	  {"id":"b","methods":["GET"],"pathPrefix":"b","upstream":"http://h"}
	]}`
	if _, f := ParseConfig([]byte(earlier)); f == nil ||
		!strings.Contains(f.Reason, "route 1") || !strings.Contains(f.Reason, `"a"`) ||
		!strings.Contains(f.Reason, "0-65535") {
		t.Fatalf("want route 1's out-of-range port to win, got %+v", f)
	}
}

// TestUpstreamPortRangeErrorPrecedenceUnchanged pins the existing selection
// order: the new content error lives in layer 4, so a layer-2 field type error
// or a layer-3 queryTransforms rule error anywhere in the document is still
// reported before an over-range port.
func TestUpstreamPortRangeErrorPrecedenceUnchanged(t *testing.T) {
	// Layer 2 beats layer 4 even when the type error is on a later route.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"p","methods":["GET"],"pathPrefix":"/p","upstream":"http://h:65536"},
	  {"id":"t","methods":"GET","pathPrefix":"/t","upstream":"http://h"}
	]}`,
		[]string{"route 2", `"t"`, "methods must be an array of strings"},
		[]string{"0-65535", "route 1", "not valid JSON"})

	// Layer 3 beats layer 4 even when the bad rule is on a later route.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"p","methods":["GET"],"pathPrefix":"/p","upstream":"http://h:65536"},
	  {"id":"r","methods":["GET"],"pathPrefix":"/r","upstream":"http://h",
	   "queryTransforms":[{"op":"frob","name":"x"}]}
	]}`,
		[]string{"route 2", `"r"`, "queryTransforms rule 1", "unknown op"},
		[]string{"0-65535", "route 1", "not valid JSON"})
}
