package contractsentinel

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func transformConfig(t *testing.T, transforms string) *Config {
	t.Helper()
	src := `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h.internal/base","queryTransforms":` + transforms + `}]}`
	return mustConfig(t, src)
}

func transformResult(t *testing.T, transforms, target string) string {
	t.Helper()
	cfg := transformConfig(t, transforms)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"`+target+`"}`)
	return res.UpstreamURL
}

func TestQueryTransformSpecExample(t *testing.T) {
	// x=%2f&a=1&%61=2&flag, then set a="" and remove flag -> x=%2f&a=
	rules := `[{"op":"set","name":"a","value":""},{"op":"remove","name":"flag"}]`
	got := transformResult(t, rules, "/p?x=%2f&a=1&%61=2&flag")
	want := "http://h.internal/base/p?x=%2f&a="
	if got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

func TestQueryTransformSet(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string // expected suffix after http://h.internal/base/p
	}{
		{
			name:      "set merges all duplicates at first hit",
			rules:     `[{"op":"set","name":"a","value":"9"}]`,
			target:    "/p?z=0&a=1&a=2&b=3",
			wantQuery: "?z=0&a=9&b=3",
		},
		{
			name:      "set matches percent-decoded duplicate names",
			rules:     `[{"op":"set","name":"a","value":""}]`,
			target:    "/p?a=1&%61=2",
			wantQuery: "?a=",
		},
		{
			name:      "set matches plus-as-space names",
			rules:     `[{"op":"set","name":"a b","value":"x"}]`,
			target:    "/p?a+b=1",
			wantQuery: "?a%20b=x",
		},
		{
			name:      "set hits parameters without an equals sign",
			rules:     `[{"op":"set","name":"flag","value":"on"}]`,
			target:    "/p?flag&x=1",
			wantQuery: "?flag=on&x=1",
		},
		{
			name:      "set replaces valueless parameter with empty value verbatim style",
			rules:     `[{"op":"set","name":"flag","value":""}]`,
			target:    "/p?flag",
			wantQuery: "?flag=",
		},
		{
			name:      "set appends an absent name at the end",
			rules:     `[{"op":"set","name":"new","value":"v"}]`,
			target:    "/p?a=1&b=2",
			wantQuery: "?a=1&b=2&new=v",
		},
		{
			name:      "set appends after an empty trailing fragment",
			rules:     `[{"op":"set","name":"n","value":"v"}]`,
			target:    "/p?a=1&",
			wantQuery: "?a=1&&n=v",
		},
		{
			name:      "set creates a query string when there is none",
			rules:     `[{"op":"set","name":"a","value":"1"}]`,
			target:    "/p",
			wantQuery: "?a=1",
		},
		{
			name:      "set on empty question mark adds the parameter",
			rules:     `[{"op":"set","name":"a","value":"1"}]`,
			target:    "/p?",
			wantQuery: "?a=1",
		},
		{
			name:      "set is case sensitive",
			rules:     `[{"op":"set","name":"A","value":"2"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&A=2",
		},
		{
			name:      "set encodes spaces utf8 and reserved characters",
			rules:     `[{"op":"set","name":"k y","value":"héllo /&=?"}]`,
			target:    "/p",
			wantQuery: "?k%20y=h%C3%A9llo%20%2F%26%3D%3F",
		},
		{
			name:      "set keeps unreserved characters raw",
			rules:     `[{"op":"set","name":"a-b_c.d~e","value":"-._~"}]`,
			target:    "/p",
			wantQuery: "?a-b_c.d~e=-._~",
		},
		{
			name:      "set uses value literally including an equals sign",
			rules:     `[{"op":"set","name":"a","value":"x=y"}]`,
			target:    "/p?a=old",
			wantQuery: "?a=x%3Dy",
		},
		{
			name:      "unmodified values keep their original lowercase escapes",
			rules:     `[{"op":"set","name":"a","value":""}]`,
			target:    "/p?x=%2f&a=1",
			wantQuery: "?x=%2f&a=",
		},
		{
			name:      "rules chain on the previous result",
			rules:     `[{"op":"set","name":"a","value":"1"},{"op":"set","name":"a","value":"2"}]`,
			target:    "/p",
			wantQuery: "?a=2",
		},
		{
			name:      "set then remove of the same name drops the query",
			rules:     `[{"op":"set","name":"a","value":"1"},{"op":"remove","name":"a"}]`,
			target:    "/p?b=2",
			wantQuery: "?b=2",
		},
		{
			name:      "remove then set appends since the name is now absent",
			rules:     `[{"op":"remove","name":"a"},{"op":"set","name":"a","value":"z"}]`,
			target:    "/p?a=1&a=2&b=3",
			wantQuery: "?b=3&a=z",
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

func TestQueryTransformSetSpecialCharNames(t *testing.T) {
	// A rule's name and value are literal text: '&', '=', '%' and '+' inside
	// them are data, never query structure. On the request side only a raw
	// '&' separates fragments and only the first raw '=' of a fragment splits
	// name from value, so an encoded "&" or "=" stays inside one name.
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string // expected suffix after http://h.internal/base/p
	}{
		{
			// Both sources decode to the same name (lowercase and uppercase
			// hex alike) and merge at the first hit's position; the encoded
			// '&' and '=' in the replacement cannot split out extra
			// parameters, and untouched fragments, the empty fragment and the
			// order all keep their original bytes.
			name:      "name and value with ampersand and equals merge at first hit",
			rules:     `[{"op":"set","name":"a&b=c","value":"x&y=z"}]`,
			target:    "/p?keep=%2f+&a%26b%3dc=1&&a%26b%3Dc=2&tail=",
			wantQuery: "?keep=%2f+&a%26b%3Dc=x%26y%3Dz&&tail=",
		},
		{
			name:      "valueless parameter with encoded name gains an equals sign",
			rules:     `[{"op":"set","name":"a&b=c","value":"v"}]`,
			target:    "/p?a%26b%3Dc",
			wantQuery: "?a%26b%3Dc=v",
		},
		{
			// The fragment "a=b=1" has name "a" and value "b=1": the rule
			// name "a=b" must not match it, so it is appended instead.
			name:      "first raw equals splits, so a=b=1 is not named a=b",
			rules:     `[{"op":"set","name":"a=b","value":"v"}]`,
			target:    "/p?a=b=1",
			wantQuery: "?a=b=1&a%3Db=v",
		},
		{
			name:      "encoded equals in the request name matches a literal equals",
			rules:     `[{"op":"set","name":"a=b","value":"v"}]`,
			target:    "/p?a%3Db=1",
			wantQuery: "?a%3Db=v",
		},
		{
			// The literal name "%26" decodes one level further than "&": it
			// matches only "%2526", never the "%26" that decodes to "&".
			name:      "literal percent escape name matches only its double-encoded form",
			rules:     `[{"op":"set","name":"%26","value":"v"}]`,
			target:    "/p?%26=1&%2526=2",
			wantQuery: "?%26=1&%2526=v",
		},
		{
			// The literal name "a+b" contains a real plus: it matches only
			// "a%2Bb". A raw '+' and "%20" both decode to a space, and a
			// decoded '+' never turns back into a space.
			name:      "literal plus name matches encoded plus only, not space forms",
			rules:     `[{"op":"set","name":"a+b","value":"v"}]`,
			target:    "/p?a+b=1&a%2Bb=2&a%20b=3",
			wantQuery: "?a+b=1&a%2Bb=v&a%20b=3",
		},
		{
			name:      "space name does not match an encoded plus",
			rules:     `[{"op":"set","name":"a b","value":"v"}]`,
			target:    "/p?a%2Bb=1",
			wantQuery: "?a%2Bb=1&a%20b=v",
		},
		{
			name:      "literal percent in the name is encoded and matched as %25",
			rules:     `[{"op":"set","name":"100%","value":"v"}]`,
			target:    "/p?100%25=1",
			wantQuery: "?100%25=v",
		},
		{
			name:      "absent special name is appended after a trailing empty fragment",
			rules:     `[{"op":"set","name":"x&y","value":"v"}]`,
			target:    "/p?a=1&",
			wantQuery: "?a=1&&x%26y=v",
		},
		{
			name:      "absent special name creates the query string",
			rules:     `[{"op":"set","name":"x&y","value":"="}]`,
			target:    "/p",
			wantQuery: "?x%26y=%3D",
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

func TestQueryTransformSetSpecialNamesDoNotAffectRouting(t *testing.T) {
	// Special characters in parameter names are query content only: route
	// selection and path joining are decided before transforms run and must
	// be unaffected by them.
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"set","name":"a&b=c","value":"x&y=z"}]},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://root.internal"}
	]}`)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/x/y?keep=%2f+&a%26b%3dc=1"}`)
	if res.RouteID != "api" {
		t.Errorf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/x/y?keep=%2f+&a%26b%3Dc=x%26y%3Dz"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// The same query on a path that only the transform-free root route
	// matches is preserved byte for byte.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other?a%26b%3dc=1&keep=%2f+"}`)
	if res.RouteID != "root" {
		t.Errorf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://root.internal/other?a%26b%3dc=1&keep=%2f+"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestQueryTransformSetInvalidEscapeNoPartialSuccess(t *testing.T) {
	// A malformed percent escape anywhere in the target fails the whole
	// request as invalid_request, even when another parameter would have
	// been replaced by the set rule: no partially rewritten query may come
	// back as a success.
	cfg := transformConfig(t, `[{"op":"set","name":"a&b=c","value":"x&y=z"}]`)
	targets := []string{
		"/p?a%26b%3dc=1&bad%zz=2", // bad escape after a replaceable parameter
		"/p?bad%zz=2&a%26b%3dc=1", // bad escape before a replaceable parameter
		"/p?a%26b%zz=1",           // bad escape inside the target name itself
		"/p?a%26b%3dc=1%2",        // truncated escape in the replaceable value
	}
	for _, target := range targets {
		// The front door: ParseRequest rejects the target outright.
		_, rf := ParseRequest([]byte(`{"method":"GET","target":"` + target + `"}`))
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("ParseRequest(%q): got %+v, want invalid_request", target, rf)
		}
		// A caller that bypasses ParseRequest still gets invalid_request from
		// Resolve whenever the malformed escape sits in a decoded name, and
		// never a partial Resolution.
		res, rf := Resolve(cfg, &Request{Method: "GET", Target: target})
		if rf != nil && rf.Code != "invalid_request" {
			t.Fatalf("Resolve(%q): got code %q, want invalid_request", target, rf.Code)
		}
		if res != nil && rf != nil {
			t.Fatalf("Resolve(%q): got both %+v and %+v, want at most one", target, res, rf)
		}
	}

	// A bad escape in a name that the set rule would have replaced is always
	// caught, even via Resolve directly.
	for _, target := range []string{"/p?a%26b%zz=1", "/p?bad%zz=2&a%26b%3dc=1"} {
		res, rf := Resolve(cfg, &Request{Method: "GET", Target: target})
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("Resolve(%q): got %+v, want invalid_request", target, rf)
		}
		if res != nil {
			t.Fatalf("Resolve(%q): got partial success %+v, want no resolution", target, res)
		}
	}
}

func TestQueryTransformRemove(t *testing.T) {
	cases := []struct {
		name      string
		ruleName  string
		target    string
		wantQuery string
	}{
		{"removes every parameter with the name", "a", "/p?a=1&b=2&a=3", "?b=2"},
		{"removes a parameter without an equals sign", "flag", "/p?flag&a=1", "?a=1"},
		{"matches decoded names", "a", "/p?%61=1&b=2", "?b=2"},
		{"matches plus as space", "a b", "/p?a+b=1", ""},
		{"does not match different case", "A", "/p?A=1&a=2", "?a=2"},
		{"no hit leaves everything verbatim", "z", "/p?a=1&b=2", "?a=1&b=2"},
		{"no hit leaves an empty question mark", "z", "/p?", "?"},
		{"removing the last fragment drops the question mark", "a", "/p?a=1", ""},
		{"removing params keeps surviving empty fragments and the mark", "a", "/p?a=1&&b=2", "?&b=2"},
		{"removing the last param but an empty fragment remains keeps the mark", "a", "/p?a=1&", "?"},
		{"removing params between empty fragments keeps their order", "a", "/p?&&a=1&&", "?&&&"},
		{"with no query string remove does not add a mark", "a", "/p", ""},
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

func TestQueryTransformRenameSpecExample(t *testing.T) {
	// old=1&new=9&%6Fld=%2f+&old&x= renamed old -> new
	rules := `[{"op":"rename","name":"old","to":"new"}]`
	got := transformResult(t, rules, "/p?old=1&new=9&%6Fld=%2f+&old&x=")
	want := "http://h.internal/base/p?new=1&new=9&new=%2f+&new&x="
	if got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

func TestQueryTransformRename(t *testing.T) {
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string // expected suffix after http://h.internal/base/p
	}{
		{
			name:      "rename every hit in place keeping values count and order",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old=1&b=2&old=3",
			wantQuery: "?new=1&b=2&new=3",
		},
		{
			name:      "rename keeps an existing target parameter without merging",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old=1&new=9&old=2",
			wantQuery: "?new=1&new=9&new=2",
		},
		{
			name:      "rename matches percent-decoded source names",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?%6Fld=1",
			wantQuery: "?new=1",
		},
		{
			name:      "rename matches plus-as-space source names",
			rules:     `[{"op":"rename","name":"a b","to":"c d"}]`,
			target:    "/p?a+b=1",
			wantQuery: "?c%20d=1",
		},
		{
			name:      "rename is case sensitive",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?OLD=1&old=2",
			wantQuery: "?OLD=1&new=2",
		},
		{
			name:      "rename keeps a valueless parameter valueless",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old&x=1",
			wantQuery: "?new&x=1",
		},
		{
			name:      "rename keeps an empty value's equals sign",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old=&x=1",
			wantQuery: "?new=&x=1",
		},
		{
			name:      "rename preserves value bytes verbatim",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old=%2f+%2F+a=b&x",
			wantQuery: "?new=%2f+%2F+a=b&x",
		},
		{
			name:      "rename encodes the new name like set",
			rules:     `[{"op":"rename","name":"old","to":"n ew/x"}]`,
			target:    "/p?old=1",
			wantQuery: "?n%20ew%2Fx=1",
		},
		{
			name:      "rename leaves non-hit fragments and empty fragments as is",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?a=1&&old=2&&",
			wantQuery: "?a=1&&new=2&&",
		},
		{
			name:      "rename with no hit changes nothing byte for byte",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?a=1&%62=2",
			wantQuery: "?a=1&%62=2",
		},
		{
			name:      "rename with no query string does not create a mark",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p",
			wantQuery: "",
		},
		{
			name:      "rename with no hit keeps an empty question mark",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?",
			wantQuery: "?",
		},
		{
			name:      "rename after a hit keeps an empty question mark with empties",
			rules:     `[{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old=1&",
			wantQuery: "?new=1&",
		},
		{
			name:      "rename to the same name does not re-encode the name",
			rules:     `[{"op":"rename","name":"a b","to":"a b"}]`,
			target:    "/p?a+b=1&a%20b=2",
			wantQuery: "?a+b=1&a%20b=2",
		},
		{
			name:      "rename chains: later set merges originals and renamed",
			rules:     `[{"op":"rename","name":"old","to":"new"},{"op":"set","name":"new","value":"z"}]`,
			target:    "/p?new=1&old=2&x=3",
			wantQuery: "?new=z&x=3",
		},
		{
			name:      "rename chains: later remove drops originals and renamed",
			rules:     `[{"op":"rename","name":"old","to":"new"},{"op":"remove","name":"new"}]`,
			target:    "/p?new=1&old=2&x=3",
			wantQuery: "?x=3",
		},
		{
			name:      "rename chains: remove source after rename hits nothing",
			rules:     `[{"op":"rename","name":"old","to":"new"},{"op":"remove","name":"old"}]`,
			target:    "/p?old=1&x=3",
			wantQuery: "?new=1&x=3",
		},
		{
			name:      "set then rename moves the merged pair",
			rules:     `[{"op":"set","name":"old","value":"z"},{"op":"rename","name":"old","to":"new"}]`,
			target:    "/p?old=1&old=2&x=3",
			wantQuery: "?new=z&x=3",
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

func TestQueryTransformChainedRenames(t *testing.T) {
	// Consecutive rename rules run strictly in array order: each rule sees the
	// names produced by the preceding rule, not the request's original names.
	// Where names collide every parameter keeps its own slot — count, value
	// and relative order are preserved; a chain never merges or overwrites the
	// way set does.
	cases := []struct {
		name      string
		rules     string
		target    string
		wantQuery string // expected suffix after http://h.internal/base/p
	}{
		{
			// The product example: a=1&b=2&a=3&c=4, a->b then b->c. The
			// original b and c parameters keep their slots; after both rules
			// all four parameters are named c, each at its original position.
			name:      "a to b then b to c collapses every slot onto c in place",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p?a=1&b=2&a=3&c=4",
			wantQuery: "?c=1&c=2&c=3&c=4",
		},
		{
			// Same two rules in the opposite order: b->c runs first on the
			// originals, so a is still named a when the second rule renames it
			// to b. Nothing is renamed twice.
			name:      "swapped rule order renames each parameter at most once",
			rules:     renameRules([2]string{"b", "c"}, [2]string{"a", "b"}),
			target:    "/p?a=1&b=2&a=3&c=4",
			wantQuery: "?b=1&c=2&b=3&c=4",
		},
		{
			// Three rules in sequence: the original a passes through b and c
			// to d; the original b passes through c to d; the original c
			// reaches d directly. Positions and values stay fixed.
			name:      "three-step chain a to b to c to d keeps slots in place",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}, [2]string{"c", "d"}),
			target:    "/p?a=1&b=2&c=3&d=4",
			wantQuery: "?d=1&d=2&d=3&d=4",
		},
		{
			// A collision chain still never merges: the renamed parameters sit
			// next to parameters already bearing the target name, duplicates
			// and all.
			name:      "chain onto an existing name keeps duplicates unmerged",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p?a=1&b=2&c=3&a=4&b=5&c=6",
			wantQuery: "?c=1&c=2&c=3&c=4&c=5&c=6",
		},
		{
			// Values — lowercase escapes, '+', extra '=' — pass through both
			// renames byte for byte; a valueless parameter stays valueless and
			// an empty value keeps its '='.
			name:      "value forms survive both renames untouched",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p?a=%2f+%2F+a=b&a&b=&x=1",
			wantQuery: "?c=%2f+%2F+a=b&c&c=&x=1",
		},
		{
			// A valueless a and an empty-valued a keep their distinct shapes
			// after two renames.
			name:      "valueless and empty-value parameters keep their forms",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p?a&a=&b=2",
			wantQuery: "?c&c=&c=2",
		},
		{
			// Empty fragments are not parameters and survive the whole chain
			// in place, including leading and trailing ones.
			name:      "empty fragments stay in place through both renames",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p?&&a=1&&b=2&",
			wantQuery: "?&&c=1&&c=2&",
		},
		{
			// The first rule's intermediate name contains a space; it is
			// encoded as %20 and the second rule names it literally (with the
			// space) and still hits.
			name:      "intermediate name with a space is matched literally",
			rules:     renameRules([2]string{"a", "mid name"}, [2]string{"mid name", "z"}),
			target:    "/p?a=1",
			wantQuery: "?z=1",
		},
		{
			// A '+' and "%20" in a request name both decode to a space, so a
			// pre-existing parameter written either way is the same literal
			// name the first rule produced and is caught by the second rule
			// together with the renamed one.
			name:      "plus and percent-20 request names are the same space name",
			rules:     renameRules([2]string{"a", "s t"}, [2]string{"s t", "z"}),
			target:    "/p?a=1&s%20t=2&s+t=3",
			wantQuery: "?z=1&z=2&z=3",
		},
		{
			// A literal '+' in a rule name is a plus, not a space. The
			// intermediate name "m+n" is encoded as m%2Bn; the second rule
			// matches that literal plus and also a pre-existing m%2Bn.
			name:      "intermediate name with a literal plus is matched literally",
			rules:     renameRules([2]string{"a", "m+n"}, [2]string{"m+n", "z"}),
			target:    "/p?a=1&m%2Bn=9",
			wantQuery: "?z=1&z=9",
		},
		{
			// After a-> "m+n" (encoded m%2Bn), a second rule for the
			// space-name "m n" must not catch it; an existing "m n" written
			// with a raw '+' is renamed instead. Literal plus and space stay
			// distinct throughout the chain.
			name:      "literal plus intermediate is distinct from a space name",
			rules:     renameRules([2]string{"a", "m+n"}, [2]string{"m n", "z"}),
			target:    "/p?a=1&m+n=7",
			wantQuery: "?m%2Bn=1&z=7",
		},
		{
			// The intermediate name is Chinese: it is emitted as UTF-8 percent
			// escapes and the next rule, given the same Chinese characters
			// literally, decodes those escapes and matches.
			name:      "intermediate name with Chinese characters is matched literally",
			rules:     renameRules([2]string{"a", "中间"}, [2]string{"中间", "z"}),
			target:    "/p?a=1",
			wantQuery: "?z=1",
		},
		{
			// Name comparison stays case sensitive at every step: a->B yields
			// uppercase B, so a later rule for lowercase b renames only the
			// original lowercase b, never the renamed parameter.
			name:      "chained matching remains case sensitive",
			rules:     renameRules([2]string{"a", "B"}, [2]string{"b", "c"}),
			target:    "/p?a=1&b=2",
			wantQuery: "?B=1&c=2",
		},
		{
			// A rule renaming a name to itself sits in the middle of the chain
			// and must not re-encode the names that exist at that point; the
			// following real rename still proceeds.
			name:      "self-rename step neither re-encodes nor stops the chain",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "b"}, [2]string{"b", "c"}),
			target:    "/p?a=1&b=2",
			wantQuery: "?c=1&c=2",
		},
		{
			// A self-rename step must leave pre-existing alternate spellings of
			// that name byte for byte (no re-encoding), while the next real
			// rename hits all decoded-equal spellings together.
			name:      "self-rename preserves plus spelling for the next rule",
			rules:     renameRules([2]string{"a", "b x"}, [2]string{"b x", "b x"}, [2]string{"b x", "c"}),
			target:    "/p?a=1&b+x=9",
			wantQuery: "?c=1&c=9",
		},
		{
			name:      "self-rename preserves percent-20 spelling for the next rule",
			rules:     renameRules([2]string{"a", "b x"}, [2]string{"b x", "b x"}, [2]string{"b x", "c"}),
			target:    "/p?a=1&b%20x=9",
			wantQuery: "?c=1&c=9",
		},
		{
			// A rule with no source parameter is a no-op that neither changes
			// bytes nor blocks the rules after it.
			name:      "no-hit rule in the middle passes the chain through",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"q", "z"}, [2]string{"b", "c"}),
			target:    "/p?a=1&a+b=2",
			wantQuery: "?c=1&a+b=2",
		},
		{
			// The first rule missing entirely leaves the originals untouched
			// for the second rule to see under their original names.
			name:      "no-hit first rule leaves names for the next rule",
			rules:     renameRules([2]string{"z", "a"}, [2]string{"a", "b"}),
			target:    "/p?a=1&z=2",
			wantQuery: "?b=1&b=2",
		},
		{
			// With no query string a rename chain neither adds a '?' nor
			// re-encodes anything.
			name:      "chain with no query string adds nothing",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p",
			wantQuery: "",
		},
		{
			// A bare '?' with no fragments keeps its shape through the chain
			// even though a rule would have matched had a parameter existed.
			name:      "chain keeps an empty question mark empty",
			rules:     renameRules([2]string{"a", "b"}, [2]string{"b", "c"}),
			target:    "/p?",
			wantQuery: "?",
		},
		{
			// No hit anywhere preserves a bare '?' as well.
			name:      "all-miss chain keeps an empty question mark",
			rules:     renameRules([2]string{"x", "y"}, [2]string{"y", "z"}),
			target:    "/p?",
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

func TestQueryTransformChainedRenameInvalidEscape(t *testing.T) {
	// A malformed percent escape still fails the whole request as
	// invalid_request: a rename chain that would otherwise reach that
	// parameter must never legitimize it, and no partially rewritten query may
	// come back as a success.
	rules := renameRules([2]string{"a", "b"}, [2]string{"b", "c"})
	cfg := transformConfig(t, rules)
	for _, target := range []string{
		"/p?a=1&bad%zz=2", // bad escape on a name unrelated to the chain
		"/p?a%zz=1&b=2",   // bad escape on a name the first rule renames
		"/p?b=2&a%zz=1",   // same, after a parameter the second rule hits
		"/p?a%2&b=2",      // truncated escape on the first rule's source name
	} {
		// The front door rejects the target before any rule runs.
		req, rf := ParseRequest([]byte(`{"method":"GET","target":"` + target + `"}`))
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("ParseRequest(%q): got %+v, want invalid_request", target, rf)
		}
		// A caller bypassing ParseRequest gets invalid_request from Resolve as
		// soon as a malformed name is decoded, and never a partial resolution.
		res, rf2 := Resolve(cfg, &Request{Method: "GET", Target: target})
		if rf2 != nil && rf2.Code != "invalid_request" {
			t.Fatalf("Resolve(%q): got code %q, want invalid_request", target, rf2.Code)
		}
		if res != nil && rf2 != nil {
			t.Fatalf("Resolve(%q): got both %+v and %+v, want at most one", target, res, rf2)
		}
		if req != nil {
			// The front door never returns a request alongside its failure.
			t.Fatalf("ParseRequest(%q) returned a request %+v with the failure", target, req)
		}
	}

	// A malformed escape inside the name the chain is about to rename is
	// always caught through Resolve directly (the name is decoded on the first
	// rule regardless of position).
	for _, target := range []string{"/p?a%zz=1", "/p?b=2&a%zz=1"} {
		res, rf := Resolve(cfg, &Request{Method: "GET", Target: target})
		if rf == nil || rf.Code != "invalid_request" {
			t.Fatalf("Resolve(%q): got %+v, want invalid_request", target, rf)
		}
		if res != nil {
			t.Fatalf("Resolve(%q): got partial success %+v, want no resolution", target, res)
		}
	}
}

func TestQueryTransformChainedRenameFullResolution(t *testing.T) {
	// The guarantee is observed on the full resolution result: route
	// selection and upstream path joining are decided before the transforms
	// run, so chained renames alter only the query string, while a route
	// without transforms keeps the query byte for byte.
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"rename","name":"a","to":"b"},{"op":"rename","name":"b","to":"c"}]},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://root.internal/base/"}
	]}`)

	// On the api route the path remainder is joined onto the upstream base
	// exactly as without transforms, and the query shows the ordered chain.
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/orders/7?a=1&b=2&a=3&c=4"}`)
	if res.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/orders/7?c=1&c=2&c=3&c=4"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// Swapping the rule order on the route swaps the result: rebuild a config
	// with the rules reversed and confirm the joined URL differs only there.
	cfgRev := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1/",
	   "queryTransforms":[{"op":"rename","name":"b","to":"c"},{"op":"rename","name":"a","to":"b"}]}
	]}`)
	res = resolveJSON(t, cfgRev, `{"method":"GET","target":"/api/orders/7?a=1&b=2&a=3&c=4"}`)
	if res.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/orders/7?b=1&c=2&b=3&c=4"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// A request that only the transform-free root route matches keeps its
	// query (duplicates, an empty value and an empty fragment included) byte
	// for byte, and path joining is unchanged.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other/path?a=1&b=2&a=&"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://root.internal/base/other/path?a=1&b=2&a=&"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// A target with no query string: the chain adds nothing and the junction
	// slash is kept as usual.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/api"}`)
	if res.RouteID != "api" || res.UpstreamURL != "http://api.internal/v1/" {
		t.Fatalf("got %+v, want api at http://api.internal/v1/", res)
	}
}

// encodeJSONString renders s as a JSON string literal for embedding in config JSON.
func encodeJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// renameRules builds a queryTransforms array of consecutive rename rules,
// each pair being {literal name, literal to}. Names keep spaces, '+' and
// non-ASCII letters literally; only JSON string escaping is applied.
func renameRules(pairs ...[2]string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"op":"rename","name":%s,"to":%s}`,
			encodeJSONString(p[0]), encodeJSONString(p[1]))
	}
	b.WriteByte(']')
	return b.String()
}

// buildWant joins the expected query suffix onto the transformed target path.
func buildWant(target, wantQuery string) string {
	base := "http://h.internal/base"
	path := target
	if q := strings.IndexByte(target, '?'); q >= 0 {
		path = target[:q]
	}
	return base + path + wantQuery
}

func TestQueryTransformFlagAndPlus(t *testing.T) {
	// remove flag and plus-decoding in one case
	got := transformResult(t, `[{"op":"remove","name":"flag"}]`, "/p?flag&a+b=1")
	if want := "http://h.internal/base/p?a+b=1"; got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

func TestQueryTransformPreservesBytesWhenEmptyOrAbsent(t *testing.T) {
	raw := "/p?a=1&b=%41%2f&&flag"

	// No queryTransforms field: byte for byte (existing behavior).
	cfg := mustConfig(t, `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h.internal/base"}]}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"`+raw+`"}`)
	if want := "http://h.internal/base" + raw; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// An empty array is the same as omitting the field.
	got := transformResult(t, `[]`, raw)
	if want := "http://h.internal/base" + raw; got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

func TestQueryTransformInvalidPercentEscape(t *testing.T) {
	cfg := transformConfig(t, `[{"op":"remove","name":"a"}]`)
	for _, target := range []string{`/p?a%zz=1`, `/p?%2=1`, `/p?a=1%2`} {
		req, rf := ParseRequest([]byte(`{"method":"GET","target":"` + target + `"}`))
		if rf == nil {
			t.Fatalf("expected invalid_request at parse for %q", target)
		}
		if rf.Code != "invalid_request" {
			t.Fatalf("code = %q, want invalid_request for %q", rf.Code, target)
		}
		// Malformed escapes in the query name also surface through Resolve
		// if a request bypasses ParseRequest.
		if req != nil {
			if _, rf2 := Resolve(cfg, req); rf2 != nil && rf2.Code != "invalid_request" {
				t.Fatalf("resolve code = %q, want invalid_request for %q", rf2.Code, target)
			}
		}
	}
}

func TestQueryTransformInvalidConfig(t *testing.T) {
	good := `"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h"`
	cases := []struct {
		name    string
		partial string // raw JSON of the queryTransforms field
		want    string // reason substring
		ruleErr bool   // whether the error names a rule (vs. the array itself)
	}{
		{"array null", `null`, "must not be null", false},
		{"array wrong type", `{}`, "must be an array", false},
		{"array is a string", `"x"`, "must be an array", false},
		{"rule null", `[null]`, "rule must not be null", true},
		{"rule not object", `[42]`, "rule must be a JSON object", true},
		{"missing op", `[{"name":"a"}]`, "op is required", true},
		{"op wrong type", `[{"op":1,"name":"a"}]`, "op must be a string", true},
		{"unknown op", `[{"op":"delete","name":"a"}]`, "unknown op", true},
		{"missing name", `[{"op":"remove"}]`, "name is required", true},
		{"name wrong type", `[{"op":"remove","name":1}]`, "name must be a non-empty string", true},
		{"name null", `[{"op":"remove","name":null}]`, "name must be a non-empty string", true},
		{"empty name", `[{"op":"remove","name":""}]`, "name must be a non-empty string", true},
		{"set missing value", `[{"op":"set","name":"a"}]`, "set requires a string value", true},
		{"set null value", `[{"op":"set","name":"a","value":null}]`, "value must be a string", true},
		{"set numeric value", `[{"op":"set","name":"a","value":1}]`, "value must be a string", true},
		{"remove with value", `[{"op":"remove","name":"a","value":"x"}]`, "remove must not include a value", true},
		{"remove with empty value still rejected", `[{"op":"remove","name":"a","value":""}]`, "remove must not include a value", true},
		{"rename missing to", `[{"op":"rename","name":"a"}]`, "rename requires a non-empty string to", true},
		{"rename null to", `[{"op":"rename","name":"a","to":null}]`, "to must be a non-empty string", true},
		{"rename numeric to", `[{"op":"rename","name":"a","to":1}]`, "to must be a non-empty string", true},
		{"rename empty to", `[{"op":"rename","name":"a","to":""}]`, "to must be a non-empty string", true},
		{"rename with value", `[{"op":"rename","name":"a","to":"b","value":"x"}]`, "rename must not include a value", true},
		{"rename with empty value still rejected", `[{"op":"rename","name":"a","to":"b","value":""}]`, "rename must not include a value", true},
		{"rename missing name", `[{"op":"rename","to":"b"}]`, "name is required", true},
		{"rename empty name", `[{"op":"rename","name":"","to":"b"}]`, "name must be a non-empty string", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{` + good + `,"queryTransforms":` + tc.partial + `}]}`
			_, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("expected invalid_config")
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			if !strings.Contains(f.Reason, "route 1") {
				t.Fatalf("reason = %q should locate route 1", f.Reason)
			}
			if tc.ruleErr && !strings.Contains(f.Reason, "rule 1") {
				t.Fatalf("reason = %q should name rule 1", f.Reason)
			}
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.want)
			}
		})
	}

	// A bad rule on a later route invalidates the whole config even when a
	// request would match an earlier, valid route.
	t.Run("bad rule located on an unhit route", func(t *testing.T) {
		src := `{"routes":[
		  {"id":"hit","methods":["*"],"pathPrefix":"/","upstream":"http://h"},
		  {"id":"miss","methods":["GET"],"pathPrefix":"/x","upstream":"http://h2","queryTransforms":[
		    {"op":"set","name":"a","value":"1"},
		    {"op":"frob","name":"a","value":"1"}
		  ]}
		]}`
		_, f := ParseConfig([]byte(src))
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("got %+v, want invalid_config", f)
		}
		for _, want := range []string{"route 2", `"miss"`, "rule 2", "unknown op"} {
			if !strings.Contains(f.Reason, want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, want)
			}
		}
	})

	// Rule index of a later rule on the first route.
	t.Run("second rule index reported", func(t *testing.T) {
		src := `{"routes":[{` + good + `,"queryTransforms":[
		  {"op":"set","name":"a","value":"1"},
		  {"op":"remove","name":"a","value":""}
		]}]}`
		_, f := ParseConfig([]byte(src))
		if f == nil || !strings.Contains(f.Reason, "rule 2") {
			t.Fatalf("got %+v, want reason naming rule 2", f)
		}
	})
}

func TestParseConfigErrorAttributionIsPerConfig(t *testing.T) {
	// Route 2 of this config has an unsupported op in its second rule; the
	// reason must always locate route 2 / "orders" / rule 2 no matter what
	// else is being parsed in the same process.
	bad := `{"routes":[
	  {"id":"ok","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"},
	  {"id":"orders","methods":["GET"],"pathPrefix":"/b","upstream":"http://h","queryTransforms":[
	    {"op":"set","name":"a","value":"1"},
	    {"op":"frob","name":"a"}
	  ]}
	]}`
	wantReason := func(f *Failure) {
		t.Helper()
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("got %+v, want invalid_config", f)
		}
		for _, want := range []string{"route 2", `"orders"`, "rule 2", "unknown op"} {
			if !strings.Contains(f.Reason, want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, want)
			}
		}
	}

	// A second config with many valid routes (each carrying transforms) and
	// a third that fails on a later route: parsing them alongside the bad
	// config must not shift its reported positions or change its outcome.
	var many strings.Builder
	many.WriteString(`{"routes":[`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		fmt.Fprintf(&many, `{"id":"g%d","methods":["*"],"pathPrefix":"/g%d","upstream":"http://h",`+
			`"queryTransforms":[{"op":"set","name":"a","value":"1"}]}`, i, i)
	}
	many.WriteString(`]}`)
	otherBad := `{"routes":[
	  {"id":"x","methods":["*"],"pathPrefix":"/x","upstream":"http://h"},
	  {"id":"y","methods":["*"],"pathPrefix":"/y","upstream":"http://h"},
	  {"id":"z","methods":["*"],"pathPrefix":"/z","upstream":"http://h","queryTransforms":null}
	]}`

	checkOthers := func() {
		t.Helper()
		if _, f := ParseConfig([]byte(many.String())); f != nil {
			t.Fatalf("valid config rejected: %+v", f)
		}
		_, f := ParseConfig([]byte(otherBad))
		if f == nil || !strings.Contains(f.Reason, "route 3") || strings.Contains(f.Reason, "rule") {
			t.Fatalf("other config reason = %+v, want route 3 with no rule index", f)
		}
	}

	// Interleaved sequentially: same attribution as parsing alone.
	checkOthers()
	_, f := ParseConfig([]byte(bad))
	wantReason(f)
	checkOthers()

	// Interleaved concurrently: goroutines parsing other configs must not
	// race with or renumber this config's error.
	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if w%2 == 0 {
					if _, f := ParseConfig([]byte(many.String())); f != nil {
						t.Errorf("valid config rejected: %+v", f)
						return
					}
				} else {
					_, f := ParseConfig([]byte(otherBad))
					if f == nil || !strings.Contains(f.Reason, "route 3") {
						t.Errorf("other config reason = %+v, want route 3", f)
						return
					}
				}
			}
		}(w)
	}
	for i := 0; i < 200; i++ {
		_, f := ParseConfig([]byte(bad))
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("got %+v, want invalid_config", f)
		}
		for _, want := range []string{"route 2", `"orders"`, "rule 2", "unknown op"} {
			if !strings.Contains(f.Reason, want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, want)
			}
		}
	}
	wg.Wait()
}

func TestQueryTransformOnlyAppliedAfterMatching(t *testing.T) {
	// Transforms must not influence matching or conflict resolution, and a
	// transform on a losing route is not executed.
	cfg := mustConfig(t, `{"routes":[
	  {"id":"wide","methods":["*"],"pathPrefix":"/x","upstream":"http://w",
	   "queryTransforms":[{"op":"set","name":"from","value":"wildcard"}]},
	  {"id":"get","methods":["GET"],"pathPrefix":"/x","upstream":"http://g",
	   "queryTransforms":[{"op":"set","name":"from","value":"concrete"}]}
	]}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/x/1?a=1"}`)
	if res.RouteID != "get" || res.UpstreamURL != "http://g/1?a=1&from=concrete" {
		t.Fatalf("got %+v", res)
	}
}
