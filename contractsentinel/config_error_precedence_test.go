package contractsentinel

import (
	"strings"
	"testing"
)

// This file pins, as regression coverage, which error ParseConfig selects and
// where it points when several errors coexist in one configuration document.
// The rules under test are the existing accept/reject rules; the precedence
// they rely on is layered in Config.UnmarshalJSON:
//
//  1. JSON syntax (a broken document is only ever a parse failure),
//  2. the routes element type and the id/methods/pathPrefix/upstream field
//     types (type errors),
//  3. queryTransforms array and rule validity (rule errors),
//  4. field contents such as a non-absolute pathPrefix, a bad method token or
//     an empty id (content errors, in Config.validate).
//
// Within one layer the earliest array position wins: routes by their position
// in the routes array and rules by their position in the route's
// queryTransforms array, never by id ordering. Every failure must hand back no
// config at all, so no half-parsed configuration can ever resolve a request.

// expectInvalidConfig parses src and requires an invalid_config Failure whose
// reason contains every want substring and none of the forbidden substrings,
// and requires ParseConfig to hand back no config. It returns the Failure for
// any extra, test-specific assertions.
func expectInvalidConfig(t *testing.T, src string, want, forbidden []string) *Failure {
	t.Helper()
	cfg, f := ParseConfig([]byte(src))
	if f == nil {
		t.Fatalf("expected invalid_config, config was accepted: %s", src)
	}
	if f.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", f.Code)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned (no half config to resolve with), got %+v", cfg)
	}
	for _, sub := range want {
		if !strings.Contains(f.Reason, sub) {
			t.Fatalf("reason = %q, want substring %q\nconfig: %s", f.Reason, sub, src)
		}
	}
	for _, sub := range forbidden {
		if strings.Contains(f.Reason, sub) {
			t.Fatalf("reason = %q must not contain %q\nconfig: %s", f.Reason, sub, src)
		}
	}
	return f
}

// TestFieldTypeErrorsBeatRuleErrors is the headline precedence: in a
// syntactically complete document, a route-element or basic-field TYPE error
// is reported before ANY queryTransforms rule error — even when the rule error
// sits on an earlier route. The reported reason targets the offending route's
// field, carries that route's valid non-empty id wherever the id appears in
// the object, and is independent of the object's field order. The document is
// legal JSON, so it must never be described as a parse failure.
func TestFieldTypeErrorsBeatRuleErrors(t *testing.T) {
	// Every config carries a bad rule on route 1 (the unknown op "frob"); each
	// also carries a type error that pass 1 must surface first instead.
	cases := []struct {
		name      string
		src       string
		want      []string
		forbidden []string
	}{
		{
			name: "route 1 unknown op masked by route 2 methods written as a string, id after methods",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"methods":"GET","id":"orders","pathPrefix":"/api/orders","upstream":"http://o"}
			]}`,
			want:      []string{"route 2", `"orders"`, "methods must be an array of strings"},
			forbidden: []string{"queryTransforms rule", "frob", "route 1", "not valid JSON"},
		},
		{
			name: "the same with the id written before the bad field",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"id":"orders","methods":"GET","pathPrefix":"/api/orders","upstream":"http://o"}
			]}`,
			want:      []string{"route 2", `"orders"`, "methods must be an array of strings"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON"},
		},
		{
			name: "the same with the route object's fields shuffled and the id last",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"upstream":"http://o","pathPrefix":"/api/orders","methods":"GET","id":"orders"}
			]}`,
			want:      []string{"route 2", `"orders"`, "methods must be an array of strings"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON"},
		},
		{
			name: "a methods type error masks a bad rule on the very same route",
			src: `{"routes":[
			  {"id":"r1","methods":"GET","pathPrefix":"/a","upstream":"http://h",
			   "queryTransforms":[{"op":"frob","name":"a"}]}
			]}`,
			want:      []string{"route 1", `"r1"`, "methods must be an array of strings"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON"},
		},
		{
			name: "route 2 pathPrefix as a number masks route 1 unknown op, id after the bad field",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"methods":["GET"],"pathPrefix":7,"id":"orders","upstream":"http://o"}
			]}`,
			want:      []string{"route 2", `"orders"`, "pathPrefix must be a string"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON"},
		},
		{
			name: "route 2 upstream as a boolean masks route 1 unknown op, id after the bad field",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"methods":["GET"],"pathPrefix":"/b","upstream":true,"id":"orders"}
			]}`,
			want:      []string{"route 2", `"orders"`, "upstream must be a string"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON"},
		},
		{
			name: "a non-string entry inside methods masks route 1 unknown op and names the entry",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"id":"orders","methods":["GET",null],"pathPrefix":"/b","upstream":"http://o"}
			]}`,
			want:      []string{"route 2", `"orders"`, "methods entry 2 must be a string"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON"},
		},
		{
			name: "a null route element on route 3 masks route 1 unknown op",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a",
			   "queryTransforms":[{"op":"frob","name":"a"}]},
			  {"id":"mid","methods":["GET"],"pathPrefix":"/m","upstream":"http://m"},
			  null
			]}`,
			want:      []string{"route 3", "route entry must be an object", "got null"},
			forbidden: []string{"queryTransforms rule", "frob", "not valid JSON", "id must"},
		},
		{
			name: "of two field type errors the earliest route in the array is reported",
			src: `{"routes":[
			  {"id":"a","methods":"GET","pathPrefix":"/a","upstream":"http://h"},
			  {"id":"b","methods":["GET"],"pathPrefix":"/b","upstream":"http://h"},
			  {"id":"c","methods":["GET"],"pathPrefix":"/c","upstream":true}
			]}`,
			want:      []string{"route 1", `"a"`, "methods must be an array of strings"},
			forbidden: []string{"route 3", "upstream must be a string", "not valid JSON"},
		},
		{
			name: "a wrong-typed id is located by position alone and still masks a bad rule",
			src: `{"routes":[
			  {"id":7,"methods":["GET"],"pathPrefix":"/a","upstream":"http://h",
			   "queryTransforms":[{"op":"frob","name":"a"}]}
			]}`,
			want:      []string{"route 1", "id must be a string"},
			forbidden: []string{"(id ", "queryTransforms rule", "frob", "not valid JSON"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectInvalidConfig(t, tc.src, tc.want, tc.forbidden)
		})
	}
}

// TestRuleErrorsBeatFieldContentErrors pins the next layer: once every element
// and field has the right JSON type, an illegal queryTransforms rule beats a
// field CONTENT error — even when the content error sits on an earlier route
// (e.g. a pathPrefix that does not start with "/"). Rule reasons keep the
// route's 1-based position, its id and the 1-based rule index.
func TestRuleErrorsBeatFieldContentErrors(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      []string
		forbidden []string
	}{
		{
			// Headline: an earlier route's non-absolute pathPrefix stays hidden
			// while a later route carries an illegal rule.
			name: "route 1 non-slash pathPrefix masked by route 2 bad rule",
			src: `{"routes":[
			  {"id":"early","methods":["GET"],"pathPrefix":"api","upstream":"http://h"},
			  {"id":"later","methods":["GET"],"pathPrefix":"/b","upstream":"http://h2",
			   "queryTransforms":[{"op":"frob","name":"x"}]}
			]}`,
			want:      []string{"route 2", `"later"`, "queryTransforms rule 1", "unknown op"},
			forbidden: []string{"route 1", "pathPrefix must start with /", "not valid JSON"},
		},
		{
			name: "a bad rule masks a content error on the same route",
			src: `{"routes":[
			  {"id":"r1","methods":["GET"],"pathPrefix":"api","upstream":"http://h",
			   "queryTransforms":[{"op":"remove","name":"a","value":"x"}]}
			]}`,
			want:      []string{"route 1", `"r1"`, "queryTransforms rule 1", "remove must not include a value"},
			forbidden: []string{"pathPrefix must start with /", "not valid JSON"},
		},
		{
			name: "route 1 illegal method token masked by route 3 bad rule",
			src: `{"routes":[
			  {"id":"e1","methods":["GE T"],"pathPrefix":"/a","upstream":"http://h"},
			  {"id":"e2","methods":["GET"],"pathPrefix":"/b","upstream":"http://h"},
			  {"id":"e3","methods":["GET"],"pathPrefix":"/c","upstream":"http://h",
			   "queryTransforms":[{"op":"rename","name":"a"}]}
			]}`,
			want:      []string{"route 3", `"e3"`, "queryTransforms rule 1", "rename requires a non-empty string to"},
			forbidden: []string{"route 1", "invalid method", "not valid JSON"},
		},
		{
			name: "route 1 empty id masked by route 2 bad rule",
			src: `{"routes":[
			  {"id":"","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"},
			  {"id":"r2","methods":["GET"],"pathPrefix":"/b","upstream":"http://h",
			   "queryTransforms":[{"op":"set","name":"a"}]}
			]}`,
			want:      []string{"route 2", `"r2"`, "queryTransforms rule 1", "set requires a string value"},
			forbidden: []string{"id must be non-empty", "not valid JSON"},
		},
		{
			name: "route 1 wrong-scheme upstream masked by route 2 bad rule",
			src: `{"routes":[
			  {"id":"e1","methods":["GET"],"pathPrefix":"/a","upstream":"ftp://h"},
			  {"id":"e2","methods":["GET"],"pathPrefix":"/b","upstream":"http://h2",
			   "queryTransforms":[{"op":"frob","name":"x"}]}
			]}`,
			want:      []string{"route 2", `"e2"`, "queryTransforms rule 1", "unknown op"},
			forbidden: []string{"absolute http or https", "not valid JSON"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectInvalidConfig(t, tc.src, tc.want, tc.forbidden)
		})
	}
}

// TestRuleErrorEarliestByArrayPosition pins that, when the illegal-rule layer
// is the one that decides, selection follows ARRAY POSITION alone: the first
// offending route in the routes array and, within it, the first offending rule
// in its queryTransforms array. Route id lexicographic order never decides.
func TestRuleErrorEarliestByArrayPosition(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      []string
		forbidden []string
	}{
		{
			// "zzz" sorts after "aaa" but appears first in the array: its rule
			// is the one reported.
			name: "route order follows the array, not the id lexicographic order",
			src: `{"routes":[
			  {"id":"zzz","methods":["GET"],"pathPrefix":"/z","upstream":"http://h",
			   "queryTransforms":[{"op":"frob","name":"z"}]},
			  {"id":"aaa","methods":["GET"],"pathPrefix":"/a","upstream":"http://h",
			   "queryTransforms":[{"op":"frob","name":"a"}]}
			]}`,
			want:      []string{"route 1", `"zzz"`, "queryTransforms rule 1", "unknown op"},
			forbidden: []string{`"aaa"`, "route 2"},
		},
		{
			// Rule 3 on route 1 beats rule 1 on route 2 because route 1 is
			// first in the routes array.
			name: "a later rule on an earlier route beats an earlier rule on a later route",
			src: `{"routes":[
			  {"id":"a","methods":["GET"],"pathPrefix":"/a","upstream":"http://h","queryTransforms":[
			    {"op":"set","name":"a","value":"1"},
			    {"op":"remove","name":"b"},
			    {"op":"frob","name":"c"}]},
			  {"id":"b","methods":["GET"],"pathPrefix":"/b","upstream":"http://h","queryTransforms":[
			    {"op":"frob","name":"z"}]}
			]}`,
			want:      []string{"route 1", `"a"`, "queryTransforms rule 3", "unknown op"},
			forbidden: []string{"queryTransforms rule 1", `"b"`, "route 2"},
		},
		{
			// Two bad rules on one route: the first in the rule array wins.
			name: "within one route the first bad rule in the rule array is reported",
			src: `{"routes":[
			  {"id":"r1","methods":["GET"],"pathPrefix":"/a","upstream":"http://h","queryTransforms":[
			    {"op":"set","name":"a","value":"1"},
			    {"op":"frob","name":"b"},
			    {"op":"rename","name":"c"}]}
			]}`,
			want:      []string{"route 1", `"r1"`, "queryTransforms rule 2", "unknown op"},
			forbidden: []string{"queryTransforms rule 3"},
		},
		{
			// Among three routes with bad rules, the middle array element wins.
			name: "the middle offending route is reported by its array position",
			src: `{"routes":[
			  {"id":"r1","methods":["GET"],"pathPrefix":"/a","upstream":"http://h",
			   "queryTransforms":[{"op":"set","name":"a","value":"1"}]},
			  {"id":"r2","methods":["GET"],"pathPrefix":"/b","upstream":"http://h",
			   "queryTransforms":[{"op":"frob","name":"x"}]},
			  {"id":"r3","methods":["GET"],"pathPrefix":"/c","upstream":"http://h",
			   "queryTransforms":[{"op":"rename","name":"c"}]}
			]}`,
			want:      []string{"route 2", `"r2"`, "queryTransforms rule 1", "unknown op"},
			forbidden: []string{"route 1", "route 3", `"r3"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectInvalidConfig(t, tc.src, tc.want, tc.forbidden)
		})
	}
}

// TestRepairingOneLayerRevealsTheNext fixes a configuration one error layer at
// a time and pins which previously masked error surfaces after each repair:
//
//	step 0: route 2 methods string (type) + route 1 unknown op (rule) + route 1
//	        non-absolute pathPrefix (content) -> the methods type error
//	step 1: methods repaired                  -> the unknown-op rule error
//	step 2: rules repaired                    -> the pathPrefix content error
//	step 3: pathPrefix repaired               -> accepted; route selection,
//	        upstream joining and query rewriting all work, and a route without
//	        transforms keeps the raw query byte for byte.
func TestRepairingOneLayerRevealsTheNext(t *testing.T) {
	step0 := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"frob","name":"a"}]},
	  {"methods":"GET","id":"orders","pathPrefix":"/api/orders","upstream":"http://orders.internal"}
	]}`
	step1 := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"frob","name":"a"}]},
	  {"id":"orders","methods":["GET"],"pathPrefix":"/api/orders","upstream":"http://orders.internal"}
	]}`
	step2 := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"api","upstream":"http://api.internal/v1",
	   "queryTransforms":[
	     {"op":"set","name":"a","value":"1"},
	     {"op":"remove","name":"flag"},
	     {"op":"rename","name":"old","to":"new"}
	   ]},
	  {"id":"orders","methods":["GET"],"pathPrefix":"/api/orders","upstream":"http://orders.internal"}
	]}`
	step3 := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[
	     {"op":"set","name":"a","value":"1"},
	     {"op":"remove","name":"flag"},
	     {"op":"rename","name":"old","to":"new"}
	   ]},
	  {"id":"orders","methods":["GET"],"pathPrefix":"/api/orders","upstream":"http://orders.internal"}
	]}`

	expectInvalidConfig(t, step0,
		[]string{"route 2", `"orders"`, "methods must be an array of strings"},
		[]string{"queryTransforms rule", "pathPrefix must start with /", "not valid JSON"})

	expectInvalidConfig(t, step1,
		[]string{"route 1", `"api"`, "queryTransforms rule 1", "unknown op"},
		[]string{"methods must be an array", "pathPrefix must start with /", "not valid JSON"})

	expectInvalidConfig(t, step2,
		[]string{"route 1", `"api"`, "pathPrefix must start with /"},
		[]string{"queryTransforms rule", "unknown op", "not valid JSON"})

	// All layers repaired: the same document now parses and resolves. The
	// request hitting the route with transforms gets selection (/api segment
	// boundary), the base-path join and all three rules applied in array
	// order: set merges a to "1", remove drops flag, rename moves old to new
	// — the surviving parameters keep their order.
	cfg := mustConfig(t, step3)
	got := resolveJSON(t, cfg, `{"method":"GET","target":"/api/items?old=1&a=9&flag&keep=1"}`)
	if got.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", got.RouteID)
	}
	if got.UpstreamURL != "http://api.internal/v1/items?new=1&a=1&keep=1" {
		t.Fatalf("upstreamURL = %q, want http://api.internal/v1/items?new=1&a=1&keep=1", got.UpstreamURL)
	}

	// The longer-prefix second route wins for its own path; it defines no
	// transforms, so its raw query (duplicates and all) is preserved verbatim.
	got = resolveJSON(t, cfg, `{"method":"GET","target":"/api/orders/7?old=1&a=9&flag&a=2"}`)
	if got.RouteID != "orders" {
		t.Fatalf("routeId = %q, want orders", got.RouteID)
	}
	if got.UpstreamURL != "http://orders.internal/7?old=1&a=9&flag&a=2" {
		t.Fatalf("upstreamURL = %q, want raw query preserved byte for byte", got.UpstreamURL)
	}
}

// TestBrokenConfigJSONGuessesNothing pins the syntax layer: once the whole
// document's JSON grammar is broken, the failure is only ever a parse failure,
// even when the document opens with a routes field or contains a complete first
// route. No field, route position or rule index may be guessed.
func TestBrokenConfigJSONGuessesNothing(t *testing.T) {
	broken := []string{
		`{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"} BROKEN`,
		`{"routes":[ BROKEN`,
		`{"routes": [{"id":"x"} broken`,
		`{not json`,
	}
	for _, src := range broken {
		t.Run(src, func(t *testing.T) {
			expectInvalidConfig(t, src,
				[]string{"not valid JSON"},
				[]string{"route 1", "route 2", "queryTransforms rule", "methods",
					"must be a JSON object", "routes must"})
		})
	}
}
