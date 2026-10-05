package contractsentinel

import (
	"strings"
	"testing"
)

// These tests pin which single error ParseConfig reports when a syntactically
// complete config carries several independent faults at once, so a user fixing
// errors one at a time always sees a stable "fix this next" reason. The frozen
// precedence is:
//
//  1. JSON syntax failure (document-wide, no field/route/rule guessed), then
//  2. top-level shape (config must be an object; routes must be an array),
//  3. route entry shape and the basic fields' JSON types, routes in array
//     order — always before any queryTransforms validation, then
//  4. queryTransforms array/rule validation, routes and rules in array order
//     — always before the basic fields' content validation, then
//  5. basic field content (non-empty id/methods, method tokens, prefix shape,
//     upstream content), routes in array order.
//
// Every rejected read also hands back no config at all, so a half-validated
// configuration can never be used to resolve a request. All of this runs
// offline; the configured upstreams never need to be reachable.

// expectInvalidConfig reads src and asserts the read fails with one
// invalid_config Failure whose reason contains every want substring and none
// of the forbidden ones, and that no Config is returned.
func expectInvalidConfig(t *testing.T, src string, want, forbidden []string) *Failure {
	t.Helper()
	cfg, f := ParseConfig([]byte(src))
	if f == nil {
		t.Fatalf("expected invalid_config, config parsed: %s", src)
	}
	if f.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config; reason: %s", f.Code, f.Reason)
	}
	if cfg != nil {
		t.Fatalf("a rejected read must return no usable config, got %+v", cfg)
	}
	for _, w := range want {
		if !strings.Contains(f.Reason, w) {
			t.Fatalf("reason = %q, want substring %q\nconfig: %s", f.Reason, w, src)
		}
	}
	for _, bad := range forbidden {
		if strings.Contains(f.Reason, bad) {
			t.Fatalf("reason = %q must not contain %q\nconfig: %s", f.Reason, bad, src)
		}
	}
	return f
}

// routeWithUnknownOp is a fully valid route whose only fault is one illegal
// queryTransforms rule (unknown op). It validates on its own, so any reported
// reason that does not name its rule proves another fault outranked it.
func routeWithUnknownOp(id, prefix string) string {
	return `{"id":"` + id + `","methods":["GET"],"pathPrefix":"` + prefix +
		`","upstream":"http://h.internal/","queryTransforms":[{"op":"frobnicate","name":"x"}]}`
}

// TestFieldTypeErrorsOutrankRuleErrors is the headline guarantee: when route 1
// has an illegal queryTransforms rule and a later route has a basic-field
// type error, the field type error is reported first. The later route's valid
// non-empty id is named even when written after the offending field, and
// reordering the route object's distinct keys must not change the reason by a
// single byte.
func TestFieldTypeErrorsOutrankRuleErrors(t *testing.T) {
	cases := []struct {
		name   string
		route2 string // route 2 object, written with its own key order
		want   []string
	}{
		{
			name:   "methods written as a string, valid id after the bad field",
			route2: `{"methods":"GET","id":"orders","pathPrefix":"/orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "methods must be an array of strings"},
		},
		{
			name:   "methods written as a string, valid id before the bad field",
			route2: `{"id":"orders","methods":"GET","pathPrefix":"/orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "methods must be an array of strings"},
		},
		{
			name:   "methods null, id after the field",
			route2: `{"methods":null,"id":"orders","pathPrefix":"/orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "methods must be an array of strings"},
		},
		{
			name:   "methods object, id after the field",
			route2: `{"methods":{"GET":true},"id":"orders","pathPrefix":"/orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "methods must be an array of strings"},
		},
		{
			name:   "numeric entry inside methods, id after the field",
			route2: `{"methods":["GET",1],"id":"orders","pathPrefix":"/orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "methods entry 2 must be a string"},
		},
		{
			name:   "null entry inside methods, id after the field",
			route2: `{"methods":[null],"id":"orders","pathPrefix":"/orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "methods entry 1 must be a string"},
		},
		{
			name:   "pathPrefix numeric, id after the field",
			route2: `{"methods":["GET"],"pathPrefix":7,"id":"orders","upstream":"http://o.internal"}`,
			want:   []string{"route 2", `"orders"`, "pathPrefix must be a string"},
		},
		{
			name:   "upstream boolean, id after the field",
			route2: `{"methods":["GET"],"pathPrefix":"/orders","upstream":true,"id":"orders"}`,
			want:   []string{"route 2", `"orders"`, "upstream must be a string"},
		},
	}
	// Route 1's illegal rule must stay hidden in every case, and a wrong field
	// type in otherwise legal JSON must never be called a syntax failure; the
	// reason must not even name route 1.
	forbidden := []string{"queryTransforms", "rule 1", "unknown op", "not valid JSON", "route 1"}

	var idAfterReason string
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[` + routeWithUnknownOp("first", "/first") + `,` + tc.route2 + `]}`
			f := expectInvalidConfig(t, src, tc.want, forbidden)
			// The first two cases are the same fault with the route object's
			// distinct keys swapped: the reported reason must be byte-identical.
			if i == 0 {
				idAfterReason = f.Reason
			} else if tc.name == "methods written as a string, valid id before the bad field" {
				if f.Reason != idAfterReason {
					t.Fatalf("key reorder changed the reason:\n id after:  %q\n id before: %q",
						idAfterReason, f.Reason)
				}
			}
		})
	}

	// Exact pin of the headline wording (id placed after the bad field still
	// identifies route 2), so wording drift is a visible regression.
	src := `{"routes":[
	  {"id":"first","methods":["GET"],"pathPrefix":"/first","upstream":"http://h.internal/",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  {"methods":"GET","id":"orders","pathPrefix":"/orders","upstream":"http://o.internal"}
	]}`
	f := expectInvalidConfig(t, src,
		[]string{`route 2 (id "orders"): methods must be an array of strings`},
		[]string{"queryTransforms", "unknown op", "rule ", "not valid JSON"})
	if f.Reason != `route 2 (id "orders"): methods must be an array of strings` {
		t.Fatalf("exact reason = %q", f.Reason)
	}
}

// TestFieldTypeErrorsOutrankRuleErrorsOnEveryRoutePosition generalizes the
// headline: type checking scans routes in array order and stops at the first
// type fault, so a type error on route 1 wins over illegal rules on later
// routes just as a type error on a later route wins over earlier rules.
func TestFieldTypeErrorsOutrankRuleErrorsOnEveryRoutePosition(t *testing.T) {
	// Field type error on route 1 outranks illegal rules on routes 2 and 3.
	src := `{"routes":[
	  {"id":"one","methods":"GET","pathPrefix":"/one","upstream":"http://h"},
	  {"id":"two","methods":["GET"],"pathPrefix":"/two","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  {"id":"three","methods":["GET"],"pathPrefix":"/three","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]}
	]}`
	expectInvalidConfig(t, src,
		[]string{`route 1 (id "one"): methods must be an array of strings`},
		[]string{"route 2", "route 3", "queryTransforms", "unknown op"})

	// Field type error on route 3 outranks illegal rules on routes 1 and 2.
	src = `{"routes":[
	  {"id":"one","methods":["GET"],"pathPrefix":"/one","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  {"id":"two","methods":["GET"],"pathPrefix":"/two","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  {"id":"three","methods":42,"pathPrefix":"/three","upstream":"http://h"}
	]}`
	expectInvalidConfig(t, src,
		[]string{`route 3 (id "three"): methods must be an array of strings`},
		[]string{"route 1", "route 2", "queryTransforms", "unknown op"})

	// A non-object element is an entry-type fault and also outranks every
	// route's rules.
	src = `{"routes":[
	  {"id":"one","methods":["GET"],"pathPrefix":"/one","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  null
	]}`
	expectInvalidConfig(t, src,
		[]string{"route 2", "route entry must be an object", "got null"},
		[]string{"queryTransforms", "unknown op", "id must"})
}

// TestRuleErrorsOutrankFieldContentErrors: once every basic field has the
// right JSON type, an illegal queryTransforms rule on a later route is
// reported before content problems on an earlier route, even when that content
// problem is a pathPrefix that does not start with '/'. Field TYPE faults
// still outrank the rules.
func TestRuleErrorsOutrankFieldContentErrors(t *testing.T) {
	// Route 2 carries the bad rule and can never serve a request aimed at
	// route 1's prefix; that must not stop its rule from invalidating the
	// whole read first.
	route2 := routeWithUnknownOp("late", "/late")
	contentBadEarlier := []struct {
		name   string
		route1 string
	}{
		{"pathPrefix not starting with slash",
			`{"id":"early","methods":["GET"],"pathPrefix":"noslash","upstream":"http://h"}`},
		{"pathPrefix with a trailing slash",
			`{"id":"early","methods":["GET"],"pathPrefix":"/early/","upstream":"http://h"}`},
		{"pathPrefix containing a query",
			`{"id":"early","methods":["GET"],"pathPrefix":"/early?x=1","upstream":"http://h"}`},
		{"illegal method token",
			`{"id":"early","methods":["GE T"],"pathPrefix":"/early","upstream":"http://h"}`},
		{"empty methods array",
			`{"id":"early","methods":[],"pathPrefix":"/early","upstream":"http://h"}`},
		{"empty id",
			`{"id":"","methods":["GET"],"pathPrefix":"/early","upstream":"http://h"}`},
		{"relative upstream",
			`{"id":"early","methods":["GET"],"pathPrefix":"/early","upstream":"/path"}`},
		{"upstream with a fragment",
			`{"id":"early","methods":["GET"],"pathPrefix":"/early","upstream":"http://h#frag"}`},
	}
	for _, tc := range contentBadEarlier {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[` + tc.route1 + `,` + route2 + `]}`
			expectInvalidConfig(t, src,
				[]string{`route 2 (id "late")`, "queryTransforms rule 1", "unknown op"},
				[]string{"route 1", "not valid JSON"})
		})
	}

	// The same later rule still loses to a field TYPE error on the earlier
	// route: type checking (pass 1) precedes rule validation (pass 2).
	src := `{"routes":[
	  {"id":"early","methods":"GET","pathPrefix":"noslash","upstream":"http://h"},
	  {"id":"late","methods":["GET"],"pathPrefix":"/late","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]}
	]}`
	expectInvalidConfig(t, src,
		[]string{`route 1 (id "early")`, "methods must be an array of strings"},
		[]string{"route 2", "queryTransforms", "unknown op", "start with /"})
}

// TestRuleErrorSelectionIsByArrayPosition fixes which rule is reported when
// several rules/routes are illegal: the earliest route in the routes array,
// and within it the earliest rule in the rule array. Ids never influence the
// choice, so a route whose id sorts late still wins when it appears first.
func TestRuleErrorSelectionIsByArrayPosition(t *testing.T) {
	// Two faulty routes; the first in the array has the lexicographically
	// later id, so any id-based tie-break would pick the wrong route.
	src := `{"routes":[
	  {"id":"zzz","methods":["GET"],"pathPrefix":"/z","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  {"id":"aaa","methods":["GET"],"pathPrefix":"/a","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]}
	]}`
	f := expectInvalidConfig(t, src,
		[]string{`route 1 (id "zzz")`, "rule 1", "unknown op"},
		[]string{`"aaa"`, "route 2"})

	// Swapping the routes' array positions swaps the reported route even
	// though the set of (id, rule) pairs is identical.
	src = `{"routes":[
	  {"id":"aaa","methods":["GET"],"pathPrefix":"/a","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]},
	  {"id":"zzz","methods":["GET"],"pathPrefix":"/z","upstream":"http://h",
	   "queryTransforms":[{"op":"frobnicate","name":"x"}]}
	]}`
	f2 := expectInvalidConfig(t, src,
		[]string{`route 1 (id "aaa")`, "rule 1", "unknown op"},
		[]string{`"zzz"`, "route 2"})
	if strings.ReplaceAll(f.Reason, "zzz", "aaa") != f2.Reason {
		t.Fatalf("only the id should differ between the two reports:\n %q\n %q", f.Reason, f2.Reason)
	}

	// Several illegal rules on one route: the earliest array rule is reported
	// with its 1-based index; a valid first rule shifts the report to rule 2,
	// and a later rule 3 stays hidden.
	src = `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/r","upstream":"http://h","queryTransforms":[
	  {"op":"set","name":"keep","value":"1"},
	  {"op":"frobnicate","name":"x"},
	  {"op":"frobnicate","name":"y"}
	]}]}`
	expectInvalidConfig(t, src,
		[]string{`route 1 (id "r")`, "rule 2:", `unknown op "frobnicate"`},
		[]string{"rule 1:", "rule 3:"})

	// Route position is the primary key: route 1's third illegal rule beats
	// route 2's first illegal rule.
	src = `{"routes":[
	  {"id":"r1","methods":["GET"],"pathPrefix":"/r1","upstream":"http://h","queryTransforms":[
	    {"op":"set","name":"a","value":"1"},
	    {"op":"set","name":"b","value":"2"},
	    {"op":"frobnicate","name":"late-rule"}]},
	  {"id":"r2","methods":["GET"],"pathPrefix":"/r2","upstream":"http://h","queryTransforms":[
	    {"op":"frobnicate","name":"early-rule"}]}
	]}`
	expectInvalidConfig(t, src,
		[]string{`route 1 (id "r1")`, "rule 3", `unknown op "frobnicate"`},
		[]string{`"r2"`, "route 2", "rule 1: unknown op"})

	// 1-based route numbering with healthy routes in front, and a non-op
	// rule fault keeps the same route/rule location format.
	src = `{"routes":[
	  {"id":"h1","methods":["GET"],"pathPrefix":"/h1","upstream":"http://h"},
	  {"id":"h2","methods":["GET"],"pathPrefix":"/h2","upstream":"http://h"},
	  {"id":"bad","methods":["GET"],"pathPrefix":"/bad","upstream":"http://h",
	   "queryTransforms":[{"op":42}]}
	]}`
	expectInvalidConfig(t, src,
		[]string{`route 3 (id "bad")`, "queryTransforms rule 1", "op must be a string"},
		[]string{"route 1", "route 2"})
}

// TestConfigRepairSequenceRevealsMaskedErrors walks one faulty document
// through the whole precedence ladder: each repair exposes exactly the fault
// the priority used to hide, and after the last repair the same document's
// routes resolve normally — route selection, upstream join and query rewriting
// included, entirely offline.
func TestConfigRepairSequenceRevealsMaskedErrors(t *testing.T) {
	// build keeps the document shape fixed while three independent faults are
	// repaired one at a time: route 2's methods type, route 1's rule and
	// route 1's prefix content.
	build := func(adminMethods, apiPrefix, apiRule string) string {
		return `{"routes":[
		  {"id":"api","methods":["GET"],"pathPrefix":` + apiPrefix + `,"upstream":"http://api.internal/v1",
		   "queryTransforms":[` + apiRule + `]},
		  {"id":"admin","methods":` + adminMethods + `,"pathPrefix":"/admin","upstream":"http://admin.internal"}
		]}`
	}

	// Stage 0: route 2 methods is a string; route 1 also has a bad prefix and
	// an unknown op. The field type fault is the only thing reported.
	src := build(`"GET"`, `"api"`, `{"op":"frobnicate","name":"old"}`)
	expectInvalidConfig(t, src,
		[]string{`route 2 (id "admin"): methods must be an array of strings`},
		[]string{"route 1", "queryTransforms", "unknown op", "start with /"})

	// Repair route 2's type: route 1's rule error surfaces, still hiding the
	// prefix content fault.
	src = build(`["GET"]`, `"api"`, `{"op":"frobnicate","name":"old"}`)
	expectInvalidConfig(t, src,
		[]string{`route 1 (id "api")`, "queryTransforms rule 1", "unknown op"},
		[]string{"route 2", "start with /"})

	// Repair the rule: the prefix content fault is the last error left.
	src = build(`["GET"]`, `"api"`, `{"op":"rename","name":"old","to":"new"}`)
	expectInvalidConfig(t, src,
		[]string{`route 1 (id "api"): pathPrefix must start with /`},
		[]string{"route 2", "queryTransforms", "unknown op"})

	// Repair the prefix: the document parses and both routes work end to end.
	src = build(`["GET"]`, `"/api"`, `{"op":"rename","name":"old","to":"new"}`)
	cfg := mustConfig(t, src)

	// Route selection + upstream join + the repaired query rule on route 1:
	// old renames to new in place and the untouched parameter survives.
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/orders/7?old=1&keep=2"}`)
	if res.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/orders/7?new=1&keep=2"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// Route 2, whose type error started the sequence, is usable too, and its
	// raw query is preserved byte for byte.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/admin/x?a=1&a="}`)
	if res.RouteID != "admin" || res.UpstreamURL != "http://admin.internal/x?a=1&a=" {
		t.Fatalf("admin route = %+v, want joined URL with verbatim query", res)
	}
}

// TestBrokenJSONIsOnlyAParseFailure separates document syntax from every
// structural fault: a JSON document whose syntax is damaged is a parse
// failure even when it opens with a complete routes array and a complete
// first route, and the reason never guesses a route, rule or field.
func TestBrokenJSONIsOnlyAParseFailure(t *testing.T) {
	docs := []string{
		// Complete first route, garbage after the array element.
		`{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"} OOPS`,
		// Complete first route including a valid rule list, then a second
		// route cut off mid-value: the syntax error still owns the document.
		`{"routes":[
		  {"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h",
		   "queryTransforms":[{"op":"rename","name":"a","to":"b"}]},
		  {"id":
		]}`,
		// Truncated inside the first route's rule array: no rule index guessed.
		`{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h","queryTransforms":[{"op":"rename"`,
	}
	for _, src := range docs {
		expectInvalidConfig(t, src,
			[]string{"not valid JSON"},
			[]string{"route ", "rule ", "queryTransforms", "must be a JSON object", "routes must"})
	}
}

// TestRuleErrorKindsAllCarryRouteAndRulePosition pins that the 1-based route
// and rule location survives for every kind of illegal rule, not just unknown
// ops, and that array-level faults (null / a non-array queryTransforms) are
// attributed to the route itself without a rule index.
func TestRuleErrorKindsAllCarryRouteAndRulePosition(t *testing.T) {
	cases := []struct {
		name    string
		field   string // raw queryTransforms field content
		want    string // reason substring describing the actual problem
		ruleIdx bool   // whether the reason must carry a rule index
	}{
		{"array null", `null`, "queryTransforms must not be null", false},
		{"array object", `{}`, "queryTransforms must be an array", false},
		{"array string", `"rules"`, "queryTransforms must be an array", false},
		{"rule null", `[null]`, "rule must not be null", true},
		{"rule number", `[42]`, "rule must be a JSON object", true},
		{"missing op", `[{"name":"a"}]`, "op is required", true},
		{"op wrong type", `[{"op":1,"name":"a"}]`, "op must be a string", true},
		{"unknown op", `[{"op":"delete","name":"a"}]`, "unknown op", true},
		{"missing name", `[{"op":"remove"}]`, "name is required", true},
		{"empty name", `[{"op":"remove","name":""}]`, "name must be a non-empty string", true},
		{"set missing value", `[{"op":"set","name":"a"}]`, "set requires a string value", true},
		{"set numeric value", `[{"op":"set","name":"a","value":1}]`, "value must be a string", true},
		{"remove with value", `[{"op":"remove","name":"a","value":"x"}]`, "remove must not include a value", true},
		{"rename missing to", `[{"op":"rename","name":"a"}]`, "rename requires a non-empty string to", true},
		{"rename empty to", `[{"op":"rename","name":"a","to":""}]`, "to must be a non-empty string", true},
		{"rename with value", `[{"op":"rename","name":"a","to":"b","value":"x"}]`, "rename must not include a value", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The bad field sits on route 2, behind a perfectly valid route 1.
			badRoute := `{"id":"late","methods":["GET"],"pathPrefix":"/late","upstream":"http://h",` +
				`"queryTransforms":` + tc.field + `}`
			src := `{"routes":[` +
				`{"id":"early","methods":["GET"],"pathPrefix":"/early","upstream":"http://h"},` +
				badRoute + `]}`
			want := []string{`route 2 (id "late")`, tc.want}
			var forbidden []string
			if tc.ruleIdx {
				want = append(want, "rule 1")
				forbidden = append(forbidden, "rule 2")
			} else {
				forbidden = append(forbidden, "rule ")
			}
			expectInvalidConfig(t, src, want, forbidden)
		})
	}
}
