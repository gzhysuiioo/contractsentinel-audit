// Regression coverage for the copy rule when parameter names themselves
// contain '&', '=' or a literal '%'. These characters are content inside a
// name, never query-string structure: a raw '&' is the only fragment
// separator and only the first raw '=' of a fragment splits its name from the
// value, while the configured name and "to" are used literally. Every case
// below goes through the public entry points — ParseConfig for reading the
// configuration and ParseRequest/Resolve for reading a request and obtaining
// a resolution — so it pins user-observable behavior rather than the internal
// rewriter.
package contractsentinel

import (
	"strings"
	"testing"
)

// TestQueryTransformCopySpecialCharNames copies names that literally carry
// '&', '=' or '%'. The request spellings use percent escapes for those bytes
// (a raw '&' or '=' could never sit inside one name), the request name is
// decoded exactly once for comparison, and the copy's new name is rendered the
// way set encodes a name. Sources keep their raw name spelling, position and
// value; each copy lands immediately after its own source; parameters already
// carrying the target name stay where they are, neither merged nor
// overwritten; and a source's first '=' plus everything after it is copied
// byte for byte.
func TestQueryTransformCopySpecialCharNames(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string // expected suffix after http://h.internal/base/p
	}{
		{
			// The headline case. Both hex casings of the source name
			// ("a%26b%3dc" and "a%26b%3Dc") decode to "a&b=c" and each gains
			// its own copy right behind it. The copy name "x=y&z" is rendered
			// as "x%3dy%26z", so it can never split into extra fragments; the
			// pre-existing x%3dy%26z=9 stays in place (no merge, no overwrite).
			// The first source's value keeps its extra '=', lowercase escape,
			// uppercase escape and '+' byte for byte; the empty value keeps
			// its '='; the valueless source gains a valueless copy; the
			// unrelated parameters, raw encoding and trailing empty fragment
			// all keep their bytes and order.
			name:   "ampersand and equals in both names are content, not structure",
			rules:  `[{"op":"copy","name":"a&b=c","to":"x=y&z"}]`,
			target: "/p?keep=%2f+&a%26b%3dc=1=%2f+%2F&x%3dy%26z=9&a%26b%3Dc=&a%26b%3Dc&&z=z",
			wantQuery: "?keep=%2f+&a%26b%3dc=1=%2f+%2F&x%3Dy%26z=1=%2f+%2F" +
				"&x%3dy%26z=9&a%26b%3Dc=&x%3Dy%26z=&a%26b%3Dc&x%3Dy%26z&&z=z",
		},
		{
			// Lowercase and uppercase percent escapes denote the same decoded
			// source name; duplicates in different positions are copied
			// independently and the unrelated fragment between them is
			// unmoved.
			name:      "lowercase and uppercase hex source spellings each get a copy",
			rules:     `[{"op":"copy","name":"a&b=c","to":"x=y&z"}]`,
			target:    "/p?a%26b%3dc=1&b=0&a%26b%3Dc=2",
			wantQuery: "?a%26b%3dc=1&x%3Dy%26z=1&b=0&a%26b%3Dc=2&x%3Dy%26z=2",
		},
		{
			// A source without '=' produces a copy without '='; an empty value
			// keeps its '=' in the copy; the source's own spelling is
			// untouched.
			name:      "valueless special source stays valueless and empty value keeps equals",
			rules:     `[{"op":"copy","name":"a&b=c","to":"x=y&z"}]`,
			target:    "/p?a%26b%3Dc&a%26b%3Dc=&x=1",
			wantQuery: "?a%26b%3Dc&x%3Dy%26z&a%26b%3Dc=&x%3Dy%26z=&x=1",
		},
		{
			// The fragment "a=b=1" is split at its first raw '=', so its name
			// is "a" and its value is "b=1". The literal rule name "a=b" must
			// not match it: nothing is copied and the bytes are unchanged.
			name:      "first raw equals splits, so a=b=1 is not a parameter named a=b",
			rules:     `[{"op":"copy","name":"a=b","to":"c"}]`,
			target:    "/p?a=b=1",
			wantQuery: "?a=b=1",
		},
		{
			// The positive contrast: an encoded '=' inside the request name
			// decodes to the literal '=' the rule names, so that parameter is
			// the source while "a=b=1" (whose name is just "a") is left alone.
			name:      "encoded equals in the request name matches the literal rule name",
			rules:     `[{"op":"copy","name":"a=b","to":"c"}]`,
			target:    "/p?a=b=1&a%3Db=2",
			wantQuery: "?a=b=1&a%3Db=2&c=2",
		},
		{
			// The rule name is the literal text "%26" — percent, 2, 6. A
			// request name is decoded only once, so "%2526" (which decodes to
			// "%26") is the hit while "%26" (which decodes to "&") is a
			// different parameter and is left untouched.
			name:      "literal percent-escape rule name matches only the double-encoded form",
			rules:     `[{"op":"copy","name":"%26","to":"c"}]`,
			target:    "/p?%26=1&%2526=2",
			wantQuery: "?%26=1&%2526=2&c=2",
		},
		{
			// Copying onto the literal name "%26" must render a double-encoded
			// copy name ("%2526"), never bytes that a parser would read as the
			// separator '&'. The existing "%26" parameter (whose decoded name
			// is "&") stays in place and is not treated as the same target.
			name:      "copy onto a literal percent-escape name is double encoded",
			rules:     `[{"op":"copy","name":"a","to":"%26"}]`,
			target:    "/p?a=1&%26=9",
			wantQuery: "?a=1&%2526=1&%26=9",
		},
		{
			// A bare literal percent in the target name is percent-encoded
			// like any other non-unreserved byte, as set does.
			name:      "literal percent in the target name is encoded as percent 25",
			rules:     `[{"op":"copy","name":"a","to":"100%"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&100%25=1",
		},
		{
			// A name with a literal percent and an encoded '=': only
			// "a%25b%3dc" (decoding once to "a%b=c") matches. The other
			// spelling decodes one level deeper ("a%b%3Dc"), is a different
			// parameter and stays put, and no copy's bytes can introduce a
			// structural separator.
			name:      "literal percent together with encoded equals matches one decoding level",
			rules:     `[{"op":"copy","name":"a%b=c","to":"d%26e"}]`,
			target:    "/p?a%25b%3dc=1&a%25b%253Dc=2",
			wantQuery: "?a%25b%3dc=1&d%2526e=1&a%25b%253Dc=2",
		},
		{
			// With no hit the query is preserved byte for byte, the trailing
			// empty fragment included.
			name:      "absent special source name changes nothing including the empty fragment",
			rules:     `[{"op":"copy","name":"z&z","to":"c"}]`,
			target:    "/p?a%26b%3dc=1&",
			wantQuery: "?a%26b%3dc=1&",
		},
		{
			// Sanity on the structural boundary: "a=1&b=2" holds two
			// parameters named "a" and "b", never one parameter whose name
			// contains '&', so a rule naming "a&b" cannot match.
			name:      "a raw separator never becomes part of a name",
			rules:     `[{"op":"copy","name":"a&b","to":"c"}]`,
			target:    "/p?a=1&b=2",
			wantQuery: "?a=1&b=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := transformResult(t, tc.rules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

// TestQueryTransformCopyThenRemoveSpecialCharNames runs the rules strictly in
// configured order: copying "a&b=c" onto "x=y&z" and then removing "x=y&z"
// deletes both the freshly inserted copies and the request's original
// parameters of that target name, while the sources survive with their
// original name encodings (lowercase and uppercase alike) and every other
// fragment keeps its bytes and order.
func TestQueryTransformCopyThenRemoveSpecialCharNames(t *testing.T) {
	rules := `[
	  {"op":"copy","name":"a&b=c","to":"x=y&z"},
	  {"op":"remove","name":"x=y&z"}
	]`
	target := "/p?keep=%2f+&a%26b%3dc=1=%2f+%2F&x%3dy%26z=9&a%26b%3Dc=&a%26b%3Dc&&z=z"
	got := transformResult(t, rules, target)
	wantQuery := "?keep=%2f+&a%26b%3dc=1=%2f+%2F&a%26b%3Dc=&a%26b%3Dc&&z=z"
	if want := buildWant(target, wantQuery); got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

// TestQueryTransformCopySpecialNamesKeepsRoutingAndJoin asserts on the whole
// Resolution: special characters in copy names are query content only, so
// route selection and upstream path joining stay exactly what they are without
// rules, and a request landing on a transform-free route is preserved byte for
// byte.
func TestQueryTransformCopySpecialNamesKeepsRoutingAndJoin(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"copy","name":"a&b=c","to":"x=y&z"}]},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://root.internal"}
	]}`)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/orders/7?a%26b%3dc=1&x%3dy%26z=9"}`)
	if res.RouteID != "api" {
		t.Errorf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/orders/7?a%26b%3dc=1&x%3Dy%26z=1&x%3dy%26z=9"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// On the transform-free route the same query survives unchanged.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other?a%26b%3dc=1&x%3dy%26z=9"}`)
	if res.RouteID != "root" {
		t.Errorf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://root.internal/other?a%26b%3dc=1&x%3dy%26z=9"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

// TestQueryTransformCopySpecialNamesRoundTrip saves a configuration whose copy
// rules carry '&', '=' and '%' in their literal names and re-reads it: the
// literal rule strings and the rule order survive (ampersand is allowed to
// appear only as a JSON escape such as \u0026 in the saved text), and the same
// request resolves to the same routeId and upstreamURL before and after the
// save.
func TestQueryTransformCopySpecialNamesRoundTrip(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h.internal/base",
	  "queryTransforms":[
	    {"op":"copy","name":"a&b=c","to":"x=y&z"},
	    {"op":"copy","name":"%26","to":"q"},
	    {"op":"remove","name":"x=y&z"}
	  ]}]}`)

	doc := string(mustMarshal(t, cfg))
	for _, want := range []string{
		`"name":"a\u0026b=c"`,
		`"to":"x=y\u0026z"`,
		`"name":"%26"`,
		`{"op":"remove","name":"x=y\u0026z"}`,
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("saved config missing %q:\n%s", want, doc)
		}
	}

	// a&b=c is copied onto x=y&z, "%26" (hit via the double-encoded %2526) is
	// copied onto q, and the final remove clears every x=y&z parameter — the
	// fresh copies and the pre-existing one alike.
	target := "/p?a%26b%3dc=1&%2526=2&x%3dy%26z=8&keep=+"
	after, _ := roundTripResolve(t, cfg, "GET", target)
	want := "http://h.internal/base/p?a%26b%3dc=1&%2526=2&q=2&keep=+"
	if after.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", after.UpstreamURL, want)
	}
}

// TestQueryTransformCopySpecialNamesInvalidEscapeStillRejected pins that no
// copy chain can launder a malformed percent escape: request names are all
// decoded up front, before any rule runs, so a truncated or non-hex escape
// fails the request as invalid_request even when a later rule would delete the
// carrying parameter. ParseRequest hands back no usable request, and a caller
// resolving an in-process request with a bad escape in a name gets no partial
// Resolution.
func TestQueryTransformCopySpecialNamesInvalidEscapeStillRejected(t *testing.T) {
	cfg := transformConfig(t, `[
	  {"op":"copy","name":"a&b=c","to":"x=y&z"},
	  {"op":"remove","name":"x=y&z"},
	  {"op":"remove","name":"bad"}
	]`)

	// Every target is rejected at the front door regardless of what the later
	// rules would have done with the carrying fragment.
	parseTargets := []struct {
		target string
		where  string
	}{
		{"/p?a%26b%zz=1", "non-hex escape inside the source name itself"},
		{"/p?a%26b%3=1", "truncated escape inside the source name itself"},
		{"/p?bad%zz=2&a%26b%3dc=1", "non-hex name a later remove would delete"},
		{"/p?a%26b%3dc=1&other%2", "truncated escape in another name"},
		{"/p?a%26b%3dc=1&keep=1%2", "truncated escape in a value the copy carries"},
	}
	for _, tc := range parseTargets {
		t.Run("parse: "+tc.where, func(t *testing.T) {
			req, rf := ParseRequest([]byte(`{"method":"GET","target":"` + tc.target + `"}`))
			if rf == nil || rf.Code != "invalid_request" {
				t.Fatalf("ParseRequest(%q): got %+v, want invalid_request", tc.target, rf)
			}
			if !strings.Contains(rf.Reason, "percent escape") {
				t.Fatalf("ParseRequest(%q): reason = %q, want it to explain the bad percent escape", tc.target, rf.Reason)
			}
			if req != nil {
				t.Fatalf("ParseRequest(%q): got a usable request %+v alongside the failure", tc.target, req)
			}
		})
	}

	// A caller that bypasses ParseRequest still fails when the bad escape sits
	// in a decoded name — names are decoded before the first copy — and never
	// receives a partial success, even though the later remove rules would
	// have removed the offending fragments.
	for _, target := range []string{
		"/p?a%26b%zz=1",
		"/p?a%26b%3=1",
		"/p?bad%zz=2&a%26b%3dc=1",
		"/p?a%26b%3dc=1&other%2",
	} {
		t.Run("resolve: "+target, func(t *testing.T) {
			res, rf := Resolve(cfg, &Request{Method: "GET", Target: target})
			if rf == nil || rf.Code != "invalid_request" {
				t.Fatalf("Resolve(%q): got %+v, want invalid_request", target, rf)
			}
			if !strings.Contains(rf.Reason, "percent escape") {
				t.Fatalf("Resolve(%q): reason = %q, want it to explain the bad percent escape", target, rf.Reason)
			}
			if res != nil {
				t.Fatalf("Resolve(%q): got partial success %+v, want no resolution", target, res)
			}
		})
	}
}
