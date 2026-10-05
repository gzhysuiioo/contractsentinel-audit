// Regression tests for the remove query transform when the configured rule
// name carries query-structure or percent-encoding characters ('&', '=', '%',
// '+' or a space). The rule name is literal text: it is never re-parsed as a
// query string or percent-decoded, while request parameter names are matched
// by their percent-decoded, '+'-as-space, case-sensitive form. These tests
// pin the complete rewritten output (surviving bytes, order, empty fragments
// and the question mark), routing independence, chaining and the rule that a
// malformed percent escape can never be cleaned away by a removal.
package contractsentinel

import "testing"

// TestQueryTransformRemoveComplexSeparatorName covers a rule name that
// contains both a separator and an equals sign. The request encodings
// a%26b%3dc and a%26b%3Dc are the same name (hex case is irrelevant), and
// every occurrence — valued, empty-valued or valueless, interspersed with
// other parameters and empty fragments — is removed while nothing else is.
func TestQueryTransformRemoveComplexSeparatorName(t *testing.T) {
	cases := []struct {
		name      string
		ruleName  string
		target    string
		wantQuery string
	}{
		{
			// The spec case: one hit with a value and an uppercase escape, one
			// valueless hit, an empty fragment between them and an empty-valued
			// survivor. Surviving bytes ("%2f+", the empty value) are untouched.
			name:      "spec example leaves survivors, fragments and bytes intact",
			ruleName:  "a&b=c",
			target:    "/p?keep=%2f+&a%26b%3Dc=1&&a%26b%3dc&tail=",
			wantQuery: "?keep=%2f+&&tail=",
		},
		{
			// Lowercase and uppercase hex encodings decode to the same name;
			// the valueless form, the empty-valued form and plain valued forms
			// all hit, and removing them all drops the query string.
			name:      "all encodings and value forms hit and the query is dropped",
			ruleName:  "a&b=c",
			target:    "/p?a%26b%3dc&a%26b%3Dc&a%26b%3Dc=&a%26b%3dc=2",
			wantQuery: "",
		},
		{
			// Hits interleaved with ordinary parameters: every hit goes, every
			// survivor keeps its position relative to the other survivors.
			name:      "multiple interleaved hits are all removed in order",
			ruleName:  "a&b=c",
			target:    "/p?z=0&a%26b%3dc&m=1&a%26b%3Dc=&n=2&a%26b%3dc=3&q=4",
			wantQuery: "?z=0&m=1&n=2&q=4",
		},
		{
			// Valueless survivors on both sides keep their valueless form.
			name:      "valueless survivors keep their form and order",
			ruleName:  "a&b=c",
			target:    "/p?m&a%26b%3dc&n",
			wantQuery: "?m&n",
		},
		{
			// Empty fragments before, between and after hits survive in place;
			// fragments parse as [hit, empty, keep=2, empty, hit].
			name:      "empty fragments keep their positions around the hits",
			ruleName:  "a&b=c",
			target:    "/p?a%26b%3dc=1&&keep=2&&a%26b%3Dc",
			wantQuery: "?&keep=2&",
		},
		{
			// The first raw '=' splits a fragment, so "a=b=c" is a parameter
			// named "a": a literal rule name of "a&b=c" (or "a=b=c") cannot
			// match it. The name in the config is data, never re-split.
			name:      "literal separator name does not match an a=b=c fragment",
			ruleName:  "a&b=c",
			target:    "/p?a=b=c",
			wantQuery: "?a=b=c",
		},
		{
			name:      "literal equals name does not match an a=b=c fragment either",
			ruleName:  "a=b=c",
			target:    "/p?a=b=c",
			wantQuery: "?a=b=c",
		},
		{
			// Sanity for the first-'=' rule: removing "a" does remove the
			// fragment "a=b=c", value and extra equals included.
			name:      "removing a removes the a=b=c fragment by its real name",
			ruleName:  "a",
			target:    "/p?a=b=c",
			wantQuery: "",
		},
		{
			// The same encoded text appearing inside another parameter's name
			// or value is not a hit: only the fragment whose decoded NAME is
			// the rule name is removed.
			name:      "encoded text inside other names and values is not removed",
			ruleName:  "a&b=c",
			target:    "/p?a=b=c&a%26b%3dc=1&x=a%26b%3Dc&y=%2526%2526&za%26b%3dcw=9",
			wantQuery: "?a=b=c&x=a%26b%3Dc&y=%2526%2526&za%26b%3dcw=9",
		},
		{
			// Matching is case-sensitive after decoding: the uppercase
			// hex-encoded name decodes to "A&B=C" and stays.
			name:      "case differs in the decoded name so the parameter stays",
			ruleName:  "a&b=c",
			target:    "/p?A%26B%3DC=1&a%26b%3dc=2",
			wantQuery: "?A%26B%3DC=1",
		},
		{
			// No hit: the whole query, including its odd encodings, stays byte
			// for byte.
			name:      "no hit leaves every fragment verbatim",
			ruleName:  "zzz",
			target:    "/p?a%26b%3dc=1&%2526&a+b=x&",
			wantQuery: "?a%26b%3dc=1&%2526&a+b=x&",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := `[{"op":"remove","name":` + encodeJSONString(tc.ruleName) + `}]`
			got := transformResult(t, rules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

// TestQueryTransformRemoveLiteralEncodingSemantics pins that the configured
// name is compared as literal text against the DECODED request name: a
// configured '%26' is one decode level beyond '&', a configured '+' is a real
// plus rather than a space, and hex-case variants of an escape still match.
func TestQueryTransformRemoveLiteralEncodingSemantics(t *testing.T) {
	cases := []struct {
		name      string
		ruleName  string
		target    string
		wantQuery string
	}{
		{
			// With a%2Bb, a+b and a%20b present, removing the literal name
			// "a+b" deletes only the encoded-plus form: raw '+' and "%20"
			// decode to a space, which is a different name.
			name:      "literal plus name matches only the encoded-plus form",
			ruleName:  "a+b",
			target:    "/p?a%2Bb=1&a+b=2&a%20b=3",
			wantQuery: "?a+b=2&a%20b=3",
		},
		{
			// Conversely the space name removes the two space forms and leaves
			// the encoded-plus parameter, raw '+' spelling and all.
			name:      "space name matches the raw-plus and percent-space forms",
			ruleName:  "a b",
			target:    "/p?a%2Bb=1&a+b=2&a%20b=3",
			wantQuery: "?a%2Bb=1",
		},
		{
			// Escaped hex digits are case-insensitive on the request side; the
			// decoded name itself is still matched case-sensitively.
			name:      "hex case hits but letter case in the name does not",
			ruleName:  "a+b",
			target:    "/p?A%2BB=1&a%2bb=2",
			wantQuery: "?A%2BB=1",
		},
		{
			// "%2526" decodes to "%26" and is removed by the literal name
			// "%26"; "%26" decodes to "&" and stays. The config name is not
			// percent-decoded again.
			name:      "literal percent-escape name matches only the double-encoded form",
			ruleName:  "%26",
			target:    "/p?%2526=1&%26=2",
			wantQuery: "?%26=2",
		},
		{
			// A literal "&" name matches the single-encoded form only.
			name:      "literal ampersand name matches only the single-encoded form",
			ruleName:  "&",
			target:    "/p?%2526=1&%26=2",
			wantQuery: "?%2526=1",
		},
		{
			// A literal '&' cannot occur structurally inside a request name,
			// but its encoded form is an ordinary parameter and is removed.
			name:      "encoded ampersand parameter is removed among ordinary ones",
			ruleName:  "&",
			target:    "/p?a=1&%26=2&b=3",
			wantQuery: "?a=1&b=3",
		},
		{
			// A literal '%' name matches "%25" and nothing shorter of one
			// decode level: "%2525" decodes to "%25", not to "%".
			name:      "literal percent name matches its single-encoded form",
			ruleName:  "%",
			target:    "/p?%25=1&%2525=2",
			wantQuery: "?%2525=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := `[{"op":"remove","name":` + encodeJSONString(tc.ruleName) + `}]`
			got := transformResult(t, rules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

// TestQueryTransformRemoveComplexNameQuestionMark pins question-mark and
// empty-fragment handling for special-character names: no hit changes
// nothing (an empty question mark included); deleting everything drops the
// mark; empty fragments left behind keep the mark and their separators.
func TestQueryTransformRemoveComplexNameQuestionMark(t *testing.T) {
	// No-hit side: a rule whose name is absent leaves the query exactly as
	// received, empty question mark and trailing fragments included.
	noHit := []struct {
		name      string
		target    string
		wantQuery string
	}{
		{"no query string never gains a mark", "/p", ""},
		{"empty question mark is kept on no hit", "/p?", "?"},
		{"unmatched parameter stays byte for byte", "/p?a%26b%3dc=1", "?a%26b%3dc=1"},
		{"unmatched valueless parameter and trailing fragment stay", "/p?a%26b%3dc&", "?a%26b%3dc&"},
	}
	noHitRules := `[{"op":"remove","name":"zz"}]`
	for _, tc := range noHit {
		t.Run("no hit: "+tc.name, func(t *testing.T) {
			got := transformResult(t, noHitRules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}

	// Hit side with the complex name.
	hitCases := []struct {
		name      string
		target    string
		wantQuery string
	}{
		{"no query string never gains a mark", "/p", ""},
		{"empty question mark is kept when nothing is removed", "/p?", "?"},
		{"sole valued hit removed drops the mark", "/p?a%26b%3dc=1", ""},
		{"sole empty-valued hit removed drops the mark", "/p?a%26b%3dc=", ""},
		{"sole valueless hit removed drops the mark", "/p?a%26b%3dc", ""},
		{"hit plus one trailing empty fragment keeps the bare mark", "/p?a%26b%3dc&", "?"},
		{"hit plus two trailing empty fragments keeps mark and separator", "/p?a%26b%3dc&&", "?&"},
		{"surviving parameter and trailing fragment keep order", "/p?x=1&a%26b%3dc&", "?x=1&"},
		{"leading empty fragment survives and keeps the mark", "/p?&a%26b%3dc", "?"},
		{"empty fragments on both sides collapse to mark and separator", "/p?&a%26b%3dc&", "?&"},
	}
	rules := `[{"op":"remove","name":` + encodeJSONString("a&b=c") + `}]`
	for _, tc := range hitCases {
		t.Run("hit: "+tc.name, func(t *testing.T) {
			got := transformResult(t, rules, tc.target)
			want := buildWant(tc.target, tc.wantQuery)
			if got != want {
				t.Errorf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

// TestQueryTransformRemoveComplexNamePreservesSurvivingBytes checks the full
// output when hits sit among parameters whose values use '+' for spaces,
// mixed-case percent escapes and extra equals signs: surviving fragments are
// re-emitted byte for byte and only the hits disappear.
func TestQueryTransformRemoveComplexNamePreservesSurvivingBytes(t *testing.T) {
	rules := `[{"op":"remove","name":` + encodeJSONString("a&b=c") + `}]`
	target := "/p?v=%2F+x%3D1&a%26b%3dc=2&w=a%26b%3Dc&a%26b%3Dc=&keep=%2f+&tail"
	got := transformResult(t, rules, target)
	want := "http://h.internal/base/p?v=%2F+x%3D1&w=a%26b%3Dc&keep=%2f+&tail"
	if got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

// TestQueryTransformRemoveComplexNameKeepsRoutingAndJoin verifies on the full
// Resolution that a special-character remove rule is query content only: the
// matched route, conflict resolution and path joining are identical to the
// rule-free behavior, and a route without transforms keeps the query byte for
// byte even when it carries such parameters.
func TestQueryTransformRemoveComplexNameKeepsRoutingAndJoin(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"remove","name":"a&b=c"}]},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://root.internal"}
	]}`)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/x/y?keep=%2f+&a%26b%3Dc=1&&a%26b%3dc&tail="}`)
	if res.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/x/y?keep=%2f+&&tail="; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// The same query on a path only the transform-free root route matches is
	// preserved byte for byte.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other?a%26b%3dc=1&keep=%2f+&a%26b%3Dc"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://root.internal/other?a%26b%3dc=1&keep=%2f+&a%26b%3Dc"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

// TestQueryTransformRemoveComplexNameConflictStillReports pins that query
// content never participates in route selection: two same-prefix routes with
// the same special-character remove rule still conflict, candidates sorted
// lexicographically, and no transform output is produced.
func TestQueryTransformRemoveComplexNameConflictStillReports(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"b","methods":["GET"],"pathPrefix":"/c","upstream":"http://b.internal",
	   "queryTransforms":[{"op":"remove","name":"a&b=c"}]},
	  {"id":"a","methods":["GET"],"pathPrefix":"/c","upstream":"http://a.internal",
	   "queryTransforms":[{"op":"remove","name":"a&b=c"}]}
	]}`)
	req, rf := ParseRequest([]byte(`{"method":"GET","target":"/c?a%26b%3dc=1&keep=2"}`))
	if rf != nil {
		t.Fatalf("unexpected parse failure: %+v", rf)
	}
	res, rf := Resolve(cfg, req)
	if rf == nil || rf.Code != "route_conflict" {
		t.Fatalf("got %+v / %+v, want route_conflict", res, rf)
	}
	if res != nil {
		t.Fatalf("got partial resolution %+v, want none on conflict", res)
	}
	wantCandidates := []string{"a", "b"}
	if len(rf.Candidates) != len(wantCandidates) {
		t.Fatalf("candidates = %v, want %v", rf.Candidates, wantCandidates)
	}
	for i := range wantCandidates {
		if rf.Candidates[i] != wantCandidates[i] {
			t.Fatalf("candidates = %v, want %v", rf.Candidates, wantCandidates)
		}
	}
}

// TestQueryTransformRemoveComplexNameInvalidEscapeNoPartialSuccess pins that
// removal can never launder a malformed percent escape into a clean success:
// the whole target is validated before rewriting, including the parameter the
// rule would have deleted (name or value, valued or valueless).
func TestQueryTransformRemoveComplexNameInvalidEscapeNoPartialSuccess(t *testing.T) {
	cfg := transformConfig(t, `[{"op":"remove","name":"a&b=c"}]`)
	targets := []string{
		"/p?a%26b%3dc=1&bad%zz=2", // bad escape in another parameter
		"/p?bad%zz=2&a%26b%3dc=1", // bad escape before the removable parameter
		"/p?a%26b%zz=1",           // bad escape inside the removed parameter's name
		"/p?a%26b%zz",             // bad escape in a valueless removed parameter
		"/p?a%26b%3dc=%zz&keep=1", // bad escape inside the removed parameter's value
		"/p?a%26b%3dc=1%2",        // truncated escape in the removed value
	}
	for _, target := range targets {
		_, rf := ParseRequest([]byte(`{"method":"GET","target":"` + target + `"}`))
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("ParseRequest(%q): got %+v, want invalid_request", target, rf)
		}
	}

	// A caller that bypasses ParseRequest still gets invalid_request from
	// Resolve whenever the malformed escape sits in a decoded name — names
	// are all decoded up front, before the remove — and never a cleaned-up
	// Resolution. The value-only cases are owned by ParseRequest's whole
	// target validation, mirroring the set rule's guarantee.
	for _, target := range []string{
		"/p?a%26b%3dc=1&bad%zz=2",
		"/p?bad%zz=2&a%26b%3dc=1",
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

// TestQueryTransformRemoveComplexNameChains checks that a special-character
// remove interacts with neighboring rules exactly like an ordinary name: a
// preceding set/rename creates or renames parameters the remove then deletes,
// a following set re-appends the encoded name, and each rule runs on the
// previous rule's result.
func TestQueryTransformRemoveComplexNameChains(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string
	}{
		{
			name:      "set then remove of the complex name drops it",
			rules:     `[{"op":"set","name":"a&b=c","value":"v"},{"op":"remove","name":"a&b=c"}]`,
			target:    "/p?x=1&a%26b%3dc=2",
			wantQuery: "?x=1",
		},
		{
			name:      "remove then set appends the encoded complex name afresh",
			rules:     `[{"op":"remove","name":"a&b=c"},{"op":"set","name":"a&b=c","value":"v"}]`,
			target:    "/p?a%26b%3dc=1&x=2",
			wantQuery: "?x=2&a%26b%3Dc=v",
		},
		{
			name:      "rename the complex name away then remove the new name",
			rules:     `[{"op":"rename","name":"a&b=c","to":"z"},{"op":"remove","name":"z"}]`,
			target:    "/p?x=1&a%26b%3dc=2",
			wantQuery: "?x=1",
		},
		{
			name:      "the same chain removes a valueless hit without adding equals",
			rules:     `[{"op":"rename","name":"a&b=c","to":"z"},{"op":"remove","name":"z"}]`,
			target:    "/p?x=1&a%26b%3dc",
			wantQuery: "?x=1",
		},
		{
			name:      "removing the old name after rename hits nothing",
			rules:     `[{"op":"rename","name":"a&b=c","to":"z"},{"op":"remove","name":"a&b=c"}]`,
			target:    "/p?x=1&a%26b%3dc=2",
			wantQuery: "?x=1&z=2",
		},
		{
			name:      "two removes in sequence each apply to the current result",
			rules:     `[{"op":"remove","name":"a&b=c"},{"op":"remove","name":"x"}]`,
			target:    "/p?x=1&a%26b%3dc=2&y=3",
			wantQuery: "?y=3",
		},
		{
			// Removing the complex name and then the separately-encoded "&"
			// parameter leaves only the trailing empty fragment: the mark
			// stays on its own.
			name:      "removing both special names leaves just the mark",
			rules:     `[{"op":"remove","name":"a&b=c"},{"op":"remove","name":"&"}]`,
			target:    "/p?a%26b%3dc&%26&",
			wantQuery: "?",
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
