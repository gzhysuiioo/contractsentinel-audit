// Regression tests for the copy query transform when the configured rule
// name or copy target carries query-structure or percent-encoding characters
// ('&', '=' or a literal '%'). Rule names and copy targets are literal text:
// they are never re-parsed as a query string or percent-decoded, while
// request parameter names are matched by their percent-decoded, '+'-as-space,
// case-sensitive form. These tests pin the complete rewritten output (source
// bytes, copy placement, existing target-name parameters, empty fragments and
// the question mark), routing independence, chaining with a later remove and
// the rule that a malformed percent escape can never be cleaned away by any
// rule.
package contractsentinel

import (
	"strings"
	"testing"
)

// TestQueryTransformCopyComplexSeparatorName covers copying a name that
// contains both a separator and an equals sign onto a target that does too.
// The request encodings a%26b%3dc and a%26b%3Dc are the same name (hex case
// is irrelevant), every occurrence produces exactly one copy placed
// immediately after its own source, the source keeps its original name
// encoding, position and value bytes, and the new name is written x%3Dy%26z.
// Parameters already carrying the target name stay in place and are never
// merged with or overwritten by the copies.
func TestQueryTransformCopyComplexSeparatorName(t *testing.T) {
	rules := `[{"op":"copy","name":"a&b=c","to":"x=y&z"}]`
	cases := []struct {
		name      string
		target    string
		wantQuery string
	}{
		{
			// The spec case: both hex cases of the encoded name hit, each
			// source keeps its own encoding and position, and each copy lands
			// directly behind its source with the target name encoded.
			name:      "both hex cases hit and each copy follows its own source",
			target:    "/p?a%26b%3dc=1&a%26b%3Dc=2",
			wantQuery: "?a%26b%3dc=1&x%3Dy%26z=1&a%26b%3Dc=2&x%3Dy%26z=2",
		},
		{
			// Parameters already named x=y&z keep their places and values; the
			// copy is inserted next to its source, never merged into or
			// overwritten onto them.
			name:      "existing target-name parameters stay put and are never merged",
			target:    "/p?x%3Dy%26z=9&a%26b%3dc=1&x%3Dy%26z=8",
			wantQuery: "?x%3Dy%26z=9&a%26b%3dc=1&x%3Dy%26z=1&x%3Dy%26z=8",
		},
		{
			// The copy keeps the source's first '=' and everything after it
			// byte for byte: '+', the lowercase and uppercase percent escapes
			// and the extra raw '=' all survive unchanged.
			name:      "copy keeps the first equals and the raw value bytes",
			target:    "/p?a%26b%3dc=%2f+%2F+a=b",
			wantQuery: "?a%26b%3dc=%2f+%2F+a=b&x%3Dy%26z=%2f+%2F+a=b",
		},
		{
			// A source without an equals sign produces a copy without one.
			name:      "valueless source gains a valueless copy",
			target:    "/p?a%26b%3dc&x=1",
			wantQuery: "?a%26b%3dc&x%3Dy%26z&x=1",
		},
		{
			// An empty value keeps its equals sign on the copy.
			name:      "empty value keeps its equals sign on the copy",
			target:    "/p?a%26b%3dc=&x=1",
			wantQuery: "?a%26b%3dc=&x%3Dy%26z=&x=1",
		},
		{
			// Non-hit parameters and empty fragments keep their original bytes
			// and order around the source and its copy.
			name:      "non-hit parameters and empty fragments keep bytes and order",
			target:    "/p?a=1&&a%26b%3dc=2&&",
			wantQuery: "?a=1&&a%26b%3dc=2&x%3Dy%26z=2&&",
		},
		{
			// The first raw '=' splits a fragment, so "a=b=1" is a parameter
			// named "a" with value "b=1": a rule named "a=b" must not match
			// it, and no copy is made (copy never appends an absent name).
			name:      "a=b=1 is named a, so a literal a=b rule does not hit",
			target:    "/p?a=b=1",
			wantQuery: "?a=b=1",
		},
		{
			// Likewise the raw fragment "a=b=c" is named "a": the complex
			// rule name cannot match it, however similar the text looks.
			name:      "literal separator name does not match an a=b=c fragment",
			target:    "/p?a=b=c",
			wantQuery: "?a=b=c",
		},
		{
			// Matching is case-sensitive after decoding: the uppercase
			// hex-encoded name decodes to "A&B=C" and is not copied.
			name:      "case differs in the decoded name so no copy is made",
			target:    "/p?A%26B%3DC=1&a%26b%3dc=2",
			wantQuery: "?A%26B%3DC=1&a%26b%3dc=2&x%3Dy%26z=2",
		},
		{
			// The same encoded text inside another parameter's name or value
			// is not a hit: only a fragment whose decoded NAME is the rule
			// name is copied.
			name:      "encoded text inside other names and values is not copied",
			target:    "/p?x=a%26b%3Dc&za%26b%3dcw=9&a%26b%3dc=1",
			wantQuery: "?x=a%26b%3Dc&za%26b%3dcw=9&a%26b%3dc=1&x%3Dy%26z=1",
		},
		{
			// No hit: the whole query, including its odd encodings, stays
			// byte for byte and no target-name parameter appears.
			name:      "no hit leaves every fragment verbatim",
			target:    "/p?a%26b%3cd=1&%2526&a+b=x&",
			wantQuery: "?a%26b%3cd=1&%2526&a+b=x&",
		},
		{
			name:      "no query string never gains a mark",
			target:    "/p",
			wantQuery: "",
		},
		{
			name:      "empty question mark is kept on no hit",
			target:    "/p?",
			wantQuery: "?",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := transformResult(t, rules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}

	// The "a=b=1 is named a" case needs the rule name "a=b", not the shared
	// complex name; run it with its own rule.
	t.Run("a=b=1 does not hit a copy rule named a=b", func(t *testing.T) {
		got := transformResult(t, `[{"op":"copy","name":"a=b","to":"c"}]`, "/p?a=b=1")
		if want := "http://h.internal/base/p?a=b=1"; got != want {
			t.Errorf("upstreamURL = %q, want %q", got, want)
		}
	})
}

// TestQueryTransformCopyLiteralEncodingSemantics pins that name comparison
// decodes the request name exactly once while the configured names are used
// as literal text: a rule named "%26" copies the double-encoded "%2526"
// parameter and never the single-encoded "%26" one, and copying onto the
// literal name "%26" writes the copy as "%2526", which can never act as a
// separator or merge with an existing "%26" parameter.
func TestQueryTransformCopyLiteralEncodingSemantics(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string
	}{
		{
			// "%2526" decodes to "%26" and is copied by the literal name
			// "%26"; "%26" decodes to "&" and is left alone. The configured
			// name is not percent-decoded again.
			name:      "literal percent-escape source copies only the double-encoded form",
			rules:     `[{"op":"copy","name":"%26","to":"n"}]`,
			target:    "/p?%26=1&%2526=2",
			wantQuery: "?%26=1&%2526=2&n=2",
		},
		{
			// Copying onto the literal name "%26" encodes the copy's name as
			// "%2526": it neither becomes a separator nor merges with the
			// existing "%26" parameter, which keeps its place and bytes.
			name:      "copying to a literal percent-escape name writes the double-encoded form",
			rules:     `[{"op":"copy","name":"a","to":"%26"}]`,
			target:    "/p?a=1&%26=2",
			wantQuery: "?a=1&%2526=1&%26=2",
		},
		{
			// A literal '%' source name matches its single-encoded form
			// "%25"; "%2525" decodes to "%25", not to "%", and stays.
			name:      "literal percent source copies only its single-encoded form",
			rules:     `[{"op":"copy","name":"%","to":"p"}]`,
			target:    "/p?%25=1&%2525=2",
			wantQuery: "?%25=1&p=1&%2525=2",
		},
		{
			// A literal '&' source name matches the single-encoded form only.
			name:      "literal ampersand source copies only the single-encoded form",
			rules:     `[{"op":"copy","name":"&","to":"n"}]`,
			target:    "/p?%2526=1&%26=2",
			wantQuery: "?%2526=1&%26=2&n=2",
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

// TestQueryTransformCopyComplexNameChainRemove pins that consecutive rules
// run in configuration order on each other's results: copying a&b=c onto
// x=y&z and then removing x=y&z deletes the fresh copies AND the parameters
// that already carried the target name, while the sources survive with their
// original encodings, positions and values.
func TestQueryTransformCopyComplexNameChainRemove(t *testing.T) {
	rules := `[{"op":"copy","name":"a&b=c","to":"x=y&z"},{"op":"remove","name":"x=y&z"}]`
	cases := []struct {
		name      string
		target    string
		wantQuery string
	}{
		{
			// The copy of the first source and the pre-existing x=y&z
			// parameter are both removed; the source keeps its lowercase
			// encoding and the survivors keep their bytes and order.
			name:      "copies and original target-name parameters are both removed",
			target:    "/p?a%26b%3dc=1&x%3Dy%26z=9&keep=%2f+",
			wantQuery: "?a%26b%3dc=1&keep=%2f+",
		},
		{
			// A valueless source and a valueless pre-existing target: both
			// target-name parameters go, the source's uppercase encoding and
			// valueless form are untouched.
			name:      "valueless source survives with its encoding and form",
			target:    "/p?a%26b%3Dc&x%3Dy%26z",
			wantQuery: "?a%26b%3Dc",
		},
		{
			// Both hex-case sources keep their own encodings after their
			// copies are removed; the empty fragment stays in place.
			name:      "every source keeps its own encoding after the chain",
			target:    "/p?a%26b%3dc=%2f+&&a%26b%3Dc=2&tail=",
			wantQuery: "?a%26b%3dc=%2f+&&a%26b%3Dc=2&tail=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := transformResult(t, rules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

// TestQueryTransformCopyComplexNameKeepsRoutingAndJoin verifies on the full
// Resolution that a special-character copy rule is query content only: the
// matched route and the upstream path joining are exactly what they are
// without rules, and a route without transforms keeps the identical query
// byte for byte.
func TestQueryTransformCopyComplexNameKeepsRoutingAndJoin(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"copy","name":"a&b=c","to":"x=y&z"}]},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://root.internal"}
	]}`)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/x/y?keep=%2f+&a%26b%3Dc=1"}`)
	if res.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/x/y?keep=%2f+&a%26b%3Dc=1&x%3Dy%26z=1"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// The same query on a path only the transform-free root route matches is
	// preserved byte for byte.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other?a%26b%3dc=1&keep=%2f+"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://root.internal/other?a%26b%3dc=1&keep=%2f+"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

// TestQueryTransformCopyComplexNameInvalidEscapeNoPartialSuccess pins that an
// incomplete or non-hex percent escape in a request parameter name fails the
// request as invalid_request even when the rule chain would have copied or
// deleted the carrying parameter: all names are decoded before any rule
// runs, so no rule can launder the malformed escape into a success and no
// partially rewritten query may come back as a Resolution.
func TestQueryTransformCopyComplexNameInvalidEscapeNoPartialSuccess(t *testing.T) {
	cfg := transformConfig(t, `[{"op":"copy","name":"a&b=c","to":"x=y&z"},{"op":"remove","name":"tmp"}]`)
	targets := []string{
		"/p?a%26b%3dc=1&tmp%zz=2", // bad escape in a parameter after a copyable one
		"/p?tmp%zz=2&a%26b%3dc=1", // bad escape before the copyable parameter
		"/p?a%26b%zz=1",           // bad escape inside the copied name itself
		"/p?a%26b%zz",             // bad escape in a valueless copied name
		"/p?a%26b%3dc=1&tmp=%zz",  // bad escape in a value
		"/p?a%26b%3dc=1%2",        // truncated escape in the copied value
	}
	for _, target := range targets {
		// The front door: ParseRequest rejects the target outright no matter
		// what the rules would have done with it.
		_, rf := ParseRequest([]byte(`{"method":"GET","target":"` + target + `"}`))
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("ParseRequest(%q): got %+v, want invalid_request", target, rf)
		}
	}

	// A caller that bypasses ParseRequest still gets invalid_request from
	// Resolve whenever the malformed escape sits in a decoded name — names
	// are all decoded up front, before the copy and the remove — and never a
	// partially rewritten Resolution.
	for _, target := range []string{
		"/p?a%26b%3dc=1&tmp%zz=2",
		"/p?tmp%zz=2&a%26b%3dc=1",
		"/p?a%26b%zz=1",
		"/p?a%26b%zz",
	} {
		res, rf := Resolve(cfg, &Request{Method: "GET", Target: target})
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("Resolve(%q): got %+v, want invalid_request", target, rf)
		}
		if res != nil {
			t.Fatalf("Resolve(%q): got partial success %+v, want no resolution", target, res)
		}
	}
}

// TestQueryTransformCopyComplexNameRoundTrip saves a config whose copy rules
// carry separator and literal-percent names through the existing JSON save
// support and re-reads it: the rules, their literal names and their order
// survive, and the same request resolves identically before and after.
func TestQueryTransformCopyComplexNameRoundTrip(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h.internal/base",
	  "queryTransforms":[
	    {"op":"copy","name":"a&b=c","to":"x=y&z"},
	    {"op":"copy","name":"%26","to":"n"},
	    {"op":"remove","name":"x=y&z"}
	  ]}]}`)

	// The saved document keeps the rules in order with their literal names:
	// no percent-encoding or decoding is applied to them on save, only JSON
	// string escaping (json.Marshal writes '&' as \u0026), which decodes
	// back to the same literal name on re-read.
	doc := string(mustMarshal(t, cfg))
	wantSequence := `"queryTransforms":[` +
		`{"op":"copy","name":"a\u0026b=c","to":"x=y\u0026z"},` +
		`{"op":"copy","name":"%26","to":"n"},` +
		`{"op":"remove","name":"x=y\u0026z"}]`
	if !strings.Contains(doc, wantSequence) {
		t.Fatalf("copy rules not preserved verbatim and in order:\n%s", doc)
	}

	// Resolving the same request before and after the save gives the same
	// routeId and upstreamURL: a&b=c is copied onto x=y&z, "%2526" (the
	// literal name "%26") is copied onto n, and the remove then deletes the
	// fresh x=y&z copy while the sources keep their original bytes.
	target := "/p?a%26b%3dc=1&%2526=2&keep=%2f+"
	after, _ := roundTripResolve(t, cfg, "GET", target)
	want := "http://h.internal/base/p?a%26b%3dc=1&%2526=2&n=2&keep=%2f+"
	if after.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", after.UpstreamURL, want)
	}
}
