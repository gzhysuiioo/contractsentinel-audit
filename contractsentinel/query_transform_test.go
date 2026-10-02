package contractsentinel

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// qtConfig builds a config with a single route whose queryTransforms are the
// raw JSON supplied (or omitted when transformsJSON is "").
func qtConfig(t *testing.T, transformsJSON string) *Config {
	t.Helper()
	src := `{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/api","upstream":"http://h/base"}]}`
	if transformsJSON != "" {
		src = `{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/api","upstream":"http://h/base","queryTransforms":` + transformsJSON + `}]}`
	}
	return mustConfig(t, src)
}

func qtResolve(t *testing.T, cfg *Config, target string) string {
	t.Helper()
	res := resolveJSON(t, cfg, `{"method":"GET","target":"`+target+`"}`)
	return res.UpstreamURL
}

func TestQueryTransformExample(t *testing.T) {
	cfg := qtConfig(t, `[{"op":"set","name":"a","value":""},{"op":"remove","name":"flag"}]`)
	got := qtResolve(t, cfg, "/api?x=%2f&a=1&%61=2&flag")
	if want := "http://h/base/?x=%2f&a="; got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

func TestQueryTransformSet(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		query string
		want  string
	}{
		{
			"set merges all matches at first position",
			`[{"op":"set","name":"a","value":"v"}]`,
			"a=1&b=2&a=3",
			"a=v&b=2",
		},
		{
			"set appends when no match",
			`[{"op":"set","name":"b","value":"2"}]`,
			"a=1",
			"a=1&b=2",
		},
		{
			"set appends to empty query",
			`[{"op":"set","name":"a","value":"1"}]`,
			"",
			"a=1",
		},
		{
			"set creates query when none existed",
			`[{"op":"set","name":"a","value":"1"}]`,
			"__NO_QUERY__",
			"a=1",
		},
		{
			"set with empty value keeps equals",
			`[{"op":"set","name":"a","value":""}]`,
			"a=1&b=2",
			"a=&b=2",
		},
		{
			"set matches param without equals",
			`[{"op":"set","name":"flag","value":"on"}]`,
			"flag&a=1",
			"flag=on&a=1",
		},
		{
			"set merges decoded-name matches",
			`[{"op":"set","name":"a","value":"z"}]`,
			"%61=1&b=2&a=3",
			"a=z&b=2",
		},
		{
			"set later rule sees earlier result",
			`[{"op":"set","name":"a","value":"1"},{"op":"set","name":"b","value":"2"}]`,
			"a=0",
			"a=1&b=2",
		},
		{
			"set rewrites value with spaces",
			`[{"op":"set","name":"a","value":"x y"}]`,
			"a=1",
			"a=x%20y",
		},
		{
			"set encodes non-ascii bytes uppercase",
			`[{"op":"set","name":"a","value":"café"}]`,
			"a=1",
			"a=caf%C3%A9",
		},
		{
			"set encodes literal name with space",
			`[{"op":"set","name":"a b","value":"1"}]`,
			"x=1",
			"x=1&a%20b=1",
		},
		{
			"set leaves unreserved name chars literal",
			`[{"op":"set","name":"A-b.c_d~e","value":"1"}]`,
			"x=1",
			"x=1&A-b.c_d~e=1",
		},
		{
			"set percent-encodes literal percent in name",
			`[{"op":"set","name":"a%b","value":"1"}]`,
			"x=1",
			"x=1&a%25b=1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := qtConfig(t, tc.rules)
			target := "/api"
			if tc.query != "__NO_QUERY__" {
				target += "?" + tc.query
			}
			got := qtResolve(t, cfg, target)
			want := "http://h/base/"
			if tc.want != "" {
				want += "?" + tc.want
			}
			if got != want {
				t.Fatalf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

func TestQueryTransformRemove(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		query string
		want  string
	}{
		{
			"remove deletes all matches",
			`[{"op":"remove","name":"a"}]`,
			"a=1&b=2&a=3",
			"b=2",
		},
		{
			"remove no match leaves query intact",
			`[{"op":"remove","name":"z"}]`,
			"a=1&b=2",
			"a=1&b=2",
		},
		{
			"remove without query creates no question mark",
			`[{"op":"remove","name":"a"}]`,
			"__NO_QUERY__",
			"",
		},
		{
			"remove all params drops question mark",
			`[{"op":"remove","name":"a"},{"op":"remove","name":"b"}]`,
			"a=1&b=2",
			"",
		},
		{
			"remove keeps empty fragment as bare question mark",
			`[{"op":"remove","name":"a"}]`,
			"a=1&",
			"__BARE_Q__",
		},
		{
			"remove keeps empty fragment between params",
			`[{"op":"remove","name":"a"}]`,
			"a=1&&b=2",
			"&b=2",
		},
		{
			"remove matches decoded name with plus as space",
			`[{"op":"remove","name":"a b"}]`,
			"a+b=1&a%20b=2&x=3",
			"x=3",
		},
		{
			"remove is case sensitive",
			`[{"op":"remove","name":"A"}]`,
			"a=1&A=2",
			"a=1",
		},
		{
			"remove matches param without equals",
			`[{"op":"remove","name":"flag"}]`,
			"flag&a=1",
			"a=1",
		},
		{
			"empty query string keeps bare question mark",
			`[{"op":"remove","name":"a"}]`,
			"",
			"__BARE_Q__",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := qtConfig(t, tc.rules)
			target := "/api"
			if tc.query != "__NO_QUERY__" {
				target += "?" + tc.query
			}
			got := qtResolve(t, cfg, target)
			want := "http://h/base/"
			switch tc.want {
			case "":
				// no question mark
			case "__BARE_Q__":
				want += "?"
			default:
				want += "?" + tc.want
			}
			if got != want {
				t.Fatalf("upstreamURL = %q, want %q", got, want)
			}
		})
	}
}

func TestQueryTransformOmittedOrEmptyPreservesBytes(t *testing.T) {
	raw := "a=1&b=2&a=&%61=3&flag&x=%2f"
	for _, transforms := range []string{"", "[]"} {
		cfg := qtConfig(t, transforms)
		got := qtResolve(t, cfg, "/api?"+raw)
		if want := "http://h/base/?" + raw; got != want {
			t.Fatalf("transforms=%q: upstreamURL = %q, want %q", transforms, got, want)
		}
	}
}

func TestQueryTransformDoesNotAffectMatching(t *testing.T) {
	// A route with transforms still matches the same way; the transform only
	// touches the query after the route is selected.
	cfg := mustConfig(t, `{"routes":[
		{"id":"r","methods":["GET"],"pathPrefix":"/api","upstream":"http://h/base",
		 "queryTransforms":[{"op":"remove","name":"a"}]}
	]}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api?a=1"}`)
	if res.RouteID != "r" {
		t.Fatalf("routeId = %q, want r", res.RouteID)
	}
	if want := "http://h/base/"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestQueryTransformOutputShape(t *testing.T) {
	cfg := qtConfig(t, `[{"op":"set","name":"a","value":"1"}]`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api?a=0"}`)
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"routeId":"r","upstreamURL":"http://h/base/?a=1"}` {
		t.Fatalf("json = %s", out)
	}
}

func TestQueryTransformInvalidConfig(t *testing.T) {
	cases := []struct {
		name      string
		transform string
		want      string // reason substring
		ruleIndex int    // 0 if no rule index expected
	}{
		{"null array", `null`, "queryTransforms must not be null", 0},
		{"null rule", `[null]`, "rule must not be null", 1},
		{"non-array", `"string"`, "queryTransforms must be an array", 0},
		{"numeric rule", `[123]`, "rule has invalid fields", 1},
		{"bad op", `[{"op":"drop","name":"a"}]`, "op must be", 1},
		{"set missing value", `[{"op":"set","name":"a"}]`, "set requires a string value", 1},
		{"set value wrong type", `[{"op":"set","name":"a","value":1}]`, "rule has invalid fields", 1},
		{"op wrong type", `[{"op":123,"name":"a"}]`, "rule has invalid fields", 1},
		{"empty name", `[{"op":"set","name":"","value":"x"}]`, "name must be a non-empty string", 1},
		{"remove with value", `[{"op":"remove","name":"a","value":"x"}]`, "remove must not have a value", 1},
		{"remove with empty value", `[{"op":"remove","name":"a","value":""}]`, "remove must not have a value", 1},
		{"second rule indexed", `[{"op":"remove","name":"ok"},{"op":"drop","name":"a"}]`, "op must be", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/api","upstream":"http://h/base","queryTransforms":` + tc.transform + `}]}`
			_, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("expected invalid_config for %s", tc.transform)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.want)
			}
			if !strings.Contains(f.Reason, "route ") {
				t.Fatalf("reason = %q should locate the route", f.Reason)
			}
			if tc.ruleIndex > 0 && !strings.Contains(f.Reason, "queryTransforms rule "+strconv.Itoa(tc.ruleIndex)) {
				t.Fatalf("reason = %q should reference rule %d", f.Reason, tc.ruleIndex)
			}
		})
	}
}

func TestQueryTransformInvalidConfigEvenWhenRouteNotHit(t *testing.T) {
	// The route carrying the bad transform is never matched, but the whole
	// config is still invalid.
	src := `{"routes":[
		{"id":"good","methods":["*"],"pathPrefix":"/api","upstream":"http://h/good"},
		{"id":"bad","methods":["*"],"pathPrefix":"/other","upstream":"http://h/bad",
		 "queryTransforms":[{"op":"nope","name":"a"}]}
	]}`
	_, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got %+v, want invalid_config", f)
	}
	if !strings.Contains(f.Reason, "route 2") {
		t.Fatalf("reason = %q should locate route 2", f.Reason)
	}
}

func TestQueryTransformInvalidPercentEscape(t *testing.T) {
	// A malformed escape in the query string is rejected at request parsing
	// time, before any transform runs.
	_, f := ParseRequest([]byte(`{"method":"GET","target":"/api?a=%zz"}`))
	if f == nil || f.Code != "invalid_request" {
		t.Fatalf("got %+v, want invalid_request", f)
	}
}
