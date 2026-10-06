package contractsentinel

import (
	"strings"
	"testing"
)

func TestQueryTransformCopySpecExample(t *testing.T) {
	// old=%2f+&new=9&old, copy old -> new: every copy follows its source, the
	// existing new=9 stays put, and the valueless old gains a valueless copy.
	rules := `[{"op":"copy","name":"old","to":"new"}]`
	got := transformResult(t, rules, "/p?old=%2f+&new=9&old")
	want := "http://h.internal/base/p?old=%2f+&new=%2f+&new=9&old&new"
	if got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

func TestQueryTransformCopy(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string // expected suffix after http://h.internal/base/p
	}{
		{
			name:      "copy every hit, each copy right after its source",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?old=1&b=2&old=3",
			wantQuery: "?old=1&new=1&b=2&old=3&new=3",
		},
		{
			name:      "copy keeps existing target parameters without merging",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?new=9&old=1&new=8",
			wantQuery: "?new=9&old=1&new=1&new=8",
		},
		{
			name:      "copy matches percent-decoded source names",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?%6Fld=1",
			wantQuery: "?%6Fld=1&new=1",
		},
		{
			name:      "copy matches plus-as-space source names",
			rules:     `[{"op":"copy","name":"a b","to":"c d"}]`,
			target:    "/p?a+b=1",
			wantQuery: "?a+b=1&c%20d=1",
		},
		{
			name:      "copy is case sensitive",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?OLD=1&old=2",
			wantQuery: "?OLD=1&old=2&new=2",
		},
		{
			name:      "copy of a valueless parameter is valueless",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?old&x=1",
			wantQuery: "?old&new&x=1",
		},
		{
			name:      "copy keeps an empty value's equals sign",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?old=&x=1",
			wantQuery: "?old=&new=&x=1",
		},
		{
			name:      "copy preserves value bytes verbatim",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?old=%2f+%2F+a=b&x",
			wantQuery: "?old=%2f+%2F+a=b&new=%2f+%2F+a=b&x",
		},
		{
			name:      "copy encodes the new name like set",
			rules:     `[{"op":"copy","name":"old","to":"n ew/x"}]`,
			target:    "/p?old=1",
			wantQuery: "?old=1&n%20ew%2Fx=1",
		},
		{
			name:      "copy leaves non-hit fragments and empty fragments as is",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?a=1&&old=2&&",
			wantQuery: "?a=1&&old=2&new=2&&",
		},
		{
			name:      "copy with no hit changes nothing byte for byte",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?a=1&%62=2",
			wantQuery: "?a=1&%62=2",
		},
		{
			name:      "copy with no query string does not create a mark",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p",
			wantQuery: "",
		},
		{
			name:      "copy with no hit keeps an empty question mark",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?",
			wantQuery: "?",
		},
		{
			name:      "copy after a hit keeps an empty question mark with empties",
			rules:     `[{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?old=1&",
			wantQuery: "?old=1&new=1&",
		},
		{
			name:      "copy to the same name neither duplicates nor re-encodes",
			rules:     `[{"op":"copy","name":"a b","to":"a b"}]`,
			target:    "/p?a+b=1&a%20b=2",
			wantQuery: "?a+b=1&a%20b=2",
		},
		{
			name:      "copy chains: later remove of the source keeps the copies",
			rules:     `[{"op":"copy","name":"old","to":"new"},{"op":"remove","name":"old"}]`,
			target:    "/p?old=1&x=3&old=2",
			wantQuery: "?new=1&x=3&new=2",
		},
		{
			name:      "copy chains: later set on the target merges copies and originals",
			rules:     `[{"op":"copy","name":"old","to":"new"},{"op":"set","name":"new","value":"z"}]`,
			target:    "/p?new=1&old=2",
			wantQuery: "?new=z&old=2",
		},
		{
			name:      "copy chains: later rename moves only the copies",
			rules:     `[{"op":"copy","name":"old","to":"new"},{"op":"rename","name":"new","to":"n2"}]`,
			target:    "/p?old=1",
			wantQuery: "?old=1&n2=1",
		},
		{
			name:      "copy after rename duplicates the renamed parameters",
			rules:     `[{"op":"rename","name":"a","to":"old"},{"op":"copy","name":"old","to":"new"}]`,
			target:    "/p?a=1",
			wantQuery: "?old=1&new=1",
		},
		{
			name:      "copy of a copy walks the chain",
			rules:     `[{"op":"copy","name":"a","to":"b"},{"op":"copy","name":"b","to":"c"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&b=1&c=1",
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

// TestQueryTransformCopySpecialNames covers the name-comparison rules across
// a copy: a literal '+' or space in the rule's to is encoded like set, and
// the source name keeps matching decoded, case-sensitive request names.
func TestQueryTransformCopySpecialNames(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string
	}{
		{
			// The literal name "a+b" matches only the encoded-plus form; the
			// space spellings ('+' and "%20") are different parameters.
			name:      "literal plus source matches encoded plus only",
			rules:     `[{"op":"copy","name":"a+b","to":"c"}]`,
			target:    "/p?a+b=1&a%2Bb=2&a%20b=3",
			wantQuery: "?a+b=1&a%2Bb=2&c=2&a%20b=3",
		},
		{
			// A space in the copy name is encoded %20, and the copy lands
			// after its source while the encoded-plus parameter is untouched.
			name:      "space copy name is encoded and source stays raw",
			rules:     `[{"op":"copy","name":"a","to":"x y"}]`,
			target:    "/p?a=1&x%2By=2",
			wantQuery: "?a=1&x%20y=1&x%2By=2",
		},
		{
			// Non-ASCII copy name: encoded like set, byte by byte.
			name:      "chinese copy name is encoded",
			rules:     `[{"op":"copy","name":"a","to":"中 文"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&%E4%B8%AD%20%E6%96%87=1",
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

// TestQueryTransformCopyOnlyAppliedAfterMatching pins that copy rules are
// query content only: they run after route selection, so a copy on a losing
// route is not executed and matching, conflict resolution and path joining
// are exactly what they are without rules.
func TestQueryTransformCopyOnlyAppliedAfterMatching(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"wide","methods":["*"],"pathPrefix":"/x","upstream":"http://w",
	   "queryTransforms":[{"op":"copy","name":"a","to":"from"}]},
	  {"id":"get","methods":["GET"],"pathPrefix":"/x","upstream":"http://g",
	   "queryTransforms":[{"op":"copy","name":"a","to":"to"}]}
	]}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/x/1?a=1"}`)
	if res.RouteID != "get" || res.UpstreamURL != "http://g/1?a=1&to=1" {
		t.Fatalf("got %+v", res)
	}

	// The wildcard route's copy applies when it wins instead.
	res = resolveJSON(t, cfg, `{"method":"POST","target":"/x/1?a=1"}`)
	if res.RouteID != "wide" || res.UpstreamURL != "http://w/1?a=1&from=1" {
		t.Fatalf("got %+v", res)
	}
}

// TestQueryTransformCopyInvalidEscapeStillRejected pins that a copy rule can
// never launder a malformed percent escape into an accepted request: all
// names are decoded before any rule runs, so copying the carrying parameter
// cannot make the request valid.
func TestQueryTransformCopyInvalidEscapeStillRejected(t *testing.T) {
	cfg := transformConfig(t, `[{"op":"copy","name":"a","to":"b"}]`)
	for _, target := range []string{"/p?a=1&b%zz=2", "/p?a%zz=1"} {
		_, rf := ParseRequest([]byte(`{"method":"GET","target":"` + target + `"}`))
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("ParseRequest(%q): got %+v, want invalid_request", target, rf)
		}
		res, rf := Resolve(cfg, &Request{Method: "GET", Target: target})
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("Resolve(%q): got %+v, want invalid_request", target, rf)
		}
		if res != nil {
			t.Fatalf("Resolve(%q): got partial success %+v, want no resolution", target, res)
		}
	}
}

// TestQueryTransformCopyRoundTrip saves a config carrying copy rules through
// the existing JSON save support and re-reads it: the copy fields, literal
// names and rule order survive, and the same request resolves identically.
func TestQueryTransformCopyRoundTrip(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h.internal/base",
	  "queryTransforms":[
	    {"op":"copy","name":"old","to":"中 文+"},
	    {"op":"copy","name":"a b","to":"c d"},
	    {"op":"remove","name":"old"}
	  ]}]}`)

	// The saved document keeps the copy rules in order with their literal
	// names and to fields, and copy never gains a value field.
	doc := string(mustMarshal(t, cfg))
	wantSequence := `"queryTransforms":[` +
		`{"op":"copy","name":"old","to":"中 文+"},` +
		`{"op":"copy","name":"a b","to":"c d"},` +
		`{"op":"remove","name":"old"}]`
	if !strings.Contains(doc, wantSequence) {
		t.Fatalf("copy rules not preserved verbatim and in order:\n%s", doc)
	}
	if strings.Contains(doc, `"op":"copy","name":"old","to":"中 文+","value"`) {
		t.Fatalf("copy must not carry a value field:\n%s", doc)
	}

	// Resolving the same request before and after the save gives the same
	// routeId and upstreamURL: old is copied onto the encoded Chinese name
	// and then removed, "a b" (matched as a+b) is copied onto "c d".
	target := "/p?old=%2f+&a+b=1&keep=%41"
	after, _ := roundTripResolve(t, cfg, "GET", target)
	want := "http://h.internal/base/p?%E4%B8%AD%20%E6%96%87%2B=%2f+&a+b=1&c%20d=1&keep=%41"
	if after.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", after.UpstreamURL, want)
	}
}
