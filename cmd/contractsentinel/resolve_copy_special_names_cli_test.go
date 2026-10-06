package main

import (
	"bytes"
	"strings"
	"testing"
)

// End-to-end regression coverage for the copy rule when parameter names
// themselves contain '&', '=' or a literal '%'. The configured name and "to"
// are literal text, while in the request a raw '&' is the only fragment
// separator and only the first raw '=' splits name from value; a request name
// is percent-decoded exactly once for matching. These tests drive the same
// boundary a user uses: the copy rule is read from the config file and the
// request arrives as one JSON document on stdin.

// copySpecialNamesConfig is the headline rule: the literal source name
// "a&b=c" is copied onto the literal target name "x=y&z".
const copySpecialNamesConfig = `{
  "routes": [
    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
     "upstream": "http://orders.internal",
     "queryTransforms": [{"op": "copy", "name": "a&b=c", "to": "x=y&z"}]}
  ]
}`

// TestResolveCLICopySpecialCharNames is the headline scenario end to end.
// Both request spellings a%26b%3dc and a%26b%3Dc hit the literal source name
// "a&b=c" (hex case-insensitive on decode), and each same-named parameter
// gains its own copy placed immediately after its source. Sources keep their
// original name encoding, position and value; the copy name is rendered
// x%3Dy%26z, so it can never read as the separators '&' and '='; the request
// parameter already named x=y&z stays where it is without being merged or
// overwritten; the first source keeps the first '=' plus everything after it
// (a '+', a lowercase and an uppercase escape and an extra '=') byte for
// byte; the empty value keeps its '='; the valueless source gains a
// valueless copy; "a=b=1" is the parameter named "a" (the first raw '='
// splits), so it is never copied; unrelated parameters and empty fragments
// keep their bytes and order.
func TestResolveCLICopySpecialCharNames(t *testing.T) {
	request := `{"method":"GET","target":"/api/orders/7` +
		`?keep=%2f+` +
		`&a%26b%3dc=1=%2f+%2F` +
		`&x%3dy%26z=9` +
		`&a%26b%3Dc=` +
		`&a%26b%3Dc` +
		`&a=b=1` +
		`&` +
		`&z=z"}`

	raw := runResolveCLI(t, copySpecialNamesConfig, request)
	success := assertResolveSuccess(t, raw)
	if success.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", success.RouteID)
	}
	wantURL := "http://orders.internal/7" +
		"?keep=%2f+" +
		"&a%26b%3dc=1=%2f+%2F" +
		"&x%3Dy%26z=1=%2f+%2F" + // copy follows its source, value verbatim
		"&x%3dy%26z=9" + // pre-existing target stays put, not merged/overwritten
		"&a%26b%3Dc=" +
		"&x%3Dy%26z=" + // empty value keeps the '='
		"&a%26b%3Dc" +
		"&x%3Dy%26z" + // valueless source gains a valueless copy
		"&a=b=1" + // named "a", not "a=b": not a copy source
		"&" +
		"&z=z"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q\nwant         %q", success.UpstreamURL, wantURL)
	}
	// The rendered copy name must stay percent-encoded: a literal '&' or '='
	// inside a name would change the query's structure, and stdout never
	// unicode-escapes the structural separators.
	if strings.Contains(success.UpstreamURL, "x=y&z") {
		t.Errorf("copy name must be encoded, got a literal x=y&z in %q", success.UpstreamURL)
	}
	if !bytes.Contains(raw.stdout, []byte("x%3Dy%26z")) {
		t.Errorf("stdout must carry the encoded copy name x%%3Dy%%26z: %s", raw.stdout)
	}
	if bytes.Contains(raw.stdout, []byte("\\u0026")) {
		t.Errorf("stdout must not unicode-escape '&': %s", raw.stdout)
	}
}

// TestResolveCLICopySpecialCharNameComparison pins the one-decode rule for
// request names against literal rule names at the command boundary: a rule
// named "%26" copies the request parameter "%2526" (which decodes once to
// "%26") and never the parameter written "%26" (which decodes to "&");
// conversely, copying another name onto the literal "%26" renders the copy
// name as "%2526", never as a structural '&'.
func TestResolveCLICopySpecialCharNameComparison(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		target  string
		wantURL string
	}{
		{
			name:    "literal percent26 source matches only the double encoded request name",
			rule:    `{"op":"copy","name":"%26","to":"c"}`,
			target:  "/p?%26=1&%2526=2",
			wantURL: "http://h.internal/base/p?%26=1&%2526=2&c=2",
		},
		{
			name:    "copy onto literal percent26 renders a double encoded name",
			rule:    `{"op":"copy","name":"a","to":"%26"}`,
			target:  "/p?a=1&%26=9",
			wantURL: "http://h.internal/base/p?a=1&%2526=1&%26=9",
		},
		{
			name:    "a raw ampersand never joins two names into one source",
			rule:    `{"op":"copy","name":"a&b","to":"c"}`,
			target:  "/p?a=1&b=2",
			wantURL: "http://h.internal/base/p?a=1&b=2",
		},
	}
	configFor := func(rule string) string {
		return `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
			`"upstream":"http://h.internal/base","queryTransforms":[` + rule + `]}]}`
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, configFor(tc.rule), request))
			if success.RouteID != "root" {
				t.Errorf("routeId = %q, want root", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.wantURL)
			}
		})
	}
}

// TestResolveCLICopyThenRemoveSpecialCharNames observes rule order end to end:
// copy "a&b=c" onto "x=y&z" first, then remove "x=y&z". The removal must
// delete both the freshly created copies and the request's pre-existing
// target parameters, while the sources survive with their original name
// encodings (lowercase and uppercase hex alike) and the rest keeps its bytes
// and order.
func TestResolveCLICopyThenRemoveSpecialCharNames(t *testing.T) {
	config := `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
		`"upstream":"http://h.internal/base","queryTransforms":[
		  {"op":"copy","name":"a&b=c","to":"x=y&z"},
		  {"op":"remove","name":"x=y&z"}
		]}]}`
	request := `{"method":"GET","target":"/p` +
		`?keep=%2f+` +
		`&a%26b%3dc=1=%2f+%2F` +
		`&x%3dy%26z=9` +
		`&a%26b%3Dc=` +
		`&a%26b%3Dc` +
		`&&z=z"}`

	success := assertResolveSuccess(t, runResolveCLI(t, config, request))
	if success.RouteID != "root" {
		t.Errorf("routeId = %q, want root", success.RouteID)
	}
	wantURL := "http://h.internal/base/p" +
		"?keep=%2f+" +
		"&a%26b%3dc=1=%2f+%2F" +
		"&a%26b%3Dc=" +
		"&a%26b%3Dc" +
		"&&z=z"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q\nwant         %q", success.UpstreamURL, wantURL)
	}
	// Every target-name parameter (copies and the pre-existing one) is gone.
	if strings.Contains(success.UpstreamURL, "%3Dy%26z") || strings.Contains(success.UpstreamURL, "%3dy") {
		t.Errorf("no x=y&z parameter may remain after the remove: %q", success.UpstreamURL)
	}
}

// TestResolveCLICopySpecialNameInvalidEscapeNoPartialSuccess pins that a copy
// chain cannot turn a malformed request into a success. A truncated or
// non-hex percent escape fails the request as invalid_request even when a
// later rule would remove the carrying parameter; stdout stays completely
// empty and the stderr reason explains the bad percent escape.
func TestResolveCLICopySpecialNameInvalidEscapeNoPartialSuccess(t *testing.T) {
	config := `{"routes":[
	  {"id":"orders","methods":["GET"],"pathPrefix":"/api/orders",
	   "upstream":"http://orders.internal",
	   "queryTransforms":[
	     {"op":"copy","name":"a&b=c","to":"x=y&z"},
	     {"op":"remove","name":"x=y&z"},
	     {"op":"remove","name":"bad"}
	   ]}
	]}`
	cases := []struct {
		name   string
		target string
	}{
		{"non hex escape in the source name itself", "/api/orders/7?a%26b%zz=1"},
		{"truncated escape in the source name itself", "/api/orders/7?a%26b%3=1"},
		{"non hex name the final remove would delete", "/api/orders/7?bad%zz=2&a%26b%3dc=1"},
		{"truncated escape in another name", "/api/orders/7?a%26b%3dc=1&other%2"},
		{"truncated escape in a value the copy carries", "/api/orders/7?a%26b%3dc=1%2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runResolveCLI(t, config, `{"method":"GET","target":"`+tc.target+`"}`)
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
			if !strings.Contains(fail.Reason, "percent escape") {
				t.Fatalf("reason = %q, want it to explain the bad percent escape", fail.Reason)
			}
		})
	}
}
