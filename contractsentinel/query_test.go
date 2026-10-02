package contractsentinel

import (
	"encoding/json"
	"strings"
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

// encodeJSONString renders s as a JSON string literal for embedding in config JSON.
func encodeJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
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
