package contractsentinel

import (
	"strings"
	"testing"
)

func TestQueryTransformCopySpecExample(t *testing.T) {
	// old=%2f+&new=9&old, copy old -> new: every copy follows its source, the
	// existing new=9 stays put, and the valueless old yields a valueless copy.
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
			name:      "every hit is copied right after its source",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?a=1&x=0&a=2",
			wantQuery: "?a=1&b=1&x=0&a=2&b=2",
		},
		{
			name:      "existing target parameters are kept without merging",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?b=9&a=1&b=8",
			wantQuery: "?b=9&a=1&b=1&b=8",
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
			name:      "valueless source yields a valueless copy",
			rules:     `[{"op":"copy","name":"flag","to":"mark"}]`,
			target:    "/p?flag&x=1",
			wantQuery: "?flag&mark&x=1",
		},
		{
			name:      "empty value keeps its equals sign",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?a=&x=1",
			wantQuery: "?a=&b=&x=1",
		},
		{
			name:      "copy preserves value bytes verbatim",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?a=%2f+%2F+a=b&x",
			wantQuery: "?a=%2f+%2F+a=b&b=%2f+%2F+a=b&x",
		},
		{
			name:      "copy encodes the new name like set",
			rules:     `[{"op":"copy","name":"a","to":"n ew/x"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&n%20ew%2Fx=1",
		},
		{
			name:      "copy leaves non-hit fragments and empty fragments as is",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?x=1&&a=2&&",
			wantQuery: "?x=1&&a=2&b=2&&",
		},
		{
			name:      "copy with no hit changes nothing byte for byte",
			rules:     `[{"op":"copy","name":"z","to":"b"}]`,
			target:    "/p?a=1&%62=2",
			wantQuery: "?a=1&%62=2",
		},
		{
			name:      "copy with no query string does not create a mark",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p",
			wantQuery: "",
		},
		{
			name:      "copy with no hit keeps an empty question mark",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?",
			wantQuery: "?",
		},
		{
			name:      "copy after a hit keeps a trailing empty fragment",
			rules:     `[{"op":"copy","name":"a","to":"b"}]`,
			target:    "/p?a=1&",
			wantQuery: "?a=1&b=1&",
		},
		{
			name:      "copy to the same name does not re-encode the name",
			rules:     `[{"op":"copy","name":"a b","to":"a b"}]`,
			target:    "/p?a+b=1&a%20b=2",
			wantQuery: "?a+b=1&a%20b=2",
		},
		{
			name:      "copies are not re-copied by their own rule",
			rules:     `[{"op":"copy","name":"a","to":"a b"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&a%20b=1",
		},
		{
			name:      "copy then remove of the source keeps the copies",
			rules:     `[{"op":"copy","name":"a","to":"b"},{"op":"remove","name":"a"}]`,
			target:    "/p?a=1&x=0&a=2",
			wantQuery: "?b=1&x=0&b=2",
		},
		{
			name:      "copy then set on the target merges copies and originals",
			rules:     `[{"op":"copy","name":"a","to":"b"},{"op":"set","name":"b","value":"z"}]`,
			target:    "/p?b=9&a=1&x=0",
			wantQuery: "?b=z&a=1&x=0",
		},
		{
			name:      "copy chains: a later copy sees the earlier copies",
			rules:     `[{"op":"copy","name":"a","to":"b"},{"op":"copy","name":"b","to":"c"}]`,
			target:    "/p?a=1",
			wantQuery: "?a=1&b=1&c=1",
		},
		{
			name:      "rename then copy duplicates the renamed parameter",
			rules:     `[{"op":"rename","name":"a","to":"b"},{"op":"copy","name":"b","to":"c"}]`,
			target:    "/p?a=1",
			wantQuery: "?b=1&c=1",
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

// TestQueryTransformCopyKeepsRoutingAndJoin asserts on the full Resolution:
// copies are query content only, decided after route selection, so matching,
// conflict resolution and path joining are exactly what they are without the
// rule, and a route without transforms keeps the identical query byte for
// byte.
func TestQueryTransformCopyKeepsRoutingAndJoin(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[{"op":"copy","name":"old","to":"new"}]},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://root.internal"}
	]}`)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/x/y?old=%2f+&new=9&old"}`)
	if res.RouteID != "api" {
		t.Errorf("routeId = %q, want api", res.RouteID)
	}
	if want := "http://api.internal/v1/x/y?old=%2f+&new=%2f+&new=9&old&new"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// The same query on a path only the transform-free root route matches is
	// preserved byte for byte.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other?old=%2f+&new=9&old"}`)
	if res.RouteID != "root" {
		t.Errorf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://root.internal/other?old=%2f+&new=9&old"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestQueryTransformCopyInvalidConfig(t *testing.T) {
	good := `"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h"`
	cases := []struct {
		name    string
		partial string // raw JSON of the queryTransforms field
		want    string // reason substring
	}{
		{"copy missing to", `[{"op":"copy","name":"a"}]`, "copy requires a non-empty string to"},
		{"copy null to", `[{"op":"copy","name":"a","to":null}]`, "to must be a non-empty string"},
		{"copy numeric to", `[{"op":"copy","name":"a","to":1}]`, "to must be a non-empty string"},
		{"copy empty to", `[{"op":"copy","name":"a","to":""}]`, "to must be a non-empty string"},
		{"copy with value", `[{"op":"copy","name":"a","to":"b","value":"x"}]`, "copy must not include a value"},
		{"copy with empty value still rejected", `[{"op":"copy","name":"a","to":"b","value":""}]`, "copy must not include a value"},
		{"copy missing name", `[{"op":"copy","to":"b"}]`, "name is required"},
		{"copy empty name", `[{"op":"copy","name":"","to":"b"}]`, "name must be a non-empty string"},
		{"copy name wrong type", `[{"op":"copy","name":1,"to":"b"}]`, "name must be a non-empty string"},
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
			for _, want := range []string{"route 1", `"r1"`, "rule 1", tc.want} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
		})
	}

	// A bad copy rule invalidates the whole config even when a request would
	// only match an earlier, valid route, and the error follows the existing
	// rule-error ordering: route position, id and 1-based rule index.
	t.Run("bad copy rule located on an unhit route", func(t *testing.T) {
		src := `{"routes":[
		  {"id":"hit","methods":["*"],"pathPrefix":"/","upstream":"http://h"},
		  {"id":"miss","methods":["GET"],"pathPrefix":"/x","upstream":"http://h2","queryTransforms":[
		    {"op":"copy","name":"a","to":"b"},
		    {"op":"copy","name":"a"}
		  ]}
		]}`
		_, f := ParseConfig([]byte(src))
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("got %+v, want invalid_config", f)
		}
		for _, want := range []string{"route 2", `"miss"`, "rule 2", "copy requires a non-empty string to"} {
			if !strings.Contains(f.Reason, want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, want)
			}
		}
	})
}

// TestQueryTransformCopySaveRoundTrip saves a config carrying copy rules
// through the existing JSON support and re-reads it: the copy fields, the
// literal names and the rule order survive, and the same request resolves to
// the same result before and after.
func TestQueryTransformCopySaveRoundTrip(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h/base",
	  "queryTransforms":[
	    {"op":"copy","name":"old","to":"n ew"},
	    {"op":"copy","name":"中 文","to":"new"},
	    {"op":"remove","name":"old"}
	  ]}]}`)

	doc := string(mustMarshal(t, cfg))
	wantSequence := `"queryTransforms":[` +
		`{"op":"copy","name":"old","to":"n ew"},` +
		`{"op":"copy","name":"中 文","to":"new"},` +
		`{"op":"remove","name":"old"}]`
	if !strings.Contains(doc, wantSequence) {
		t.Fatalf("copy rules not preserved verbatim and in order:\n%s", doc)
	}
	// copy carries to but never a value, and no null may appear.
	if strings.Contains(doc, `"op":"copy","name":"old","to":"n ew","value"`) ||
		strings.Contains(doc, "null") {
		t.Fatalf("copy field shape violated:\n%s", doc)
	}

	target := "/p?old=%2f+&%E4%B8%AD%20%E6%96%87=9&keep=1"
	after, saved := roundTripResolve(t, cfg, "GET", target)
	// old is copied to "n ew" (encoded) and removed; the Chinese-named
	// parameter is copied to new; keep is untouched.
	wantQuery := "?n%20ew=%2f+&%E4%B8%AD%20%E6%96%87=9&new=9&keep=1"
	if !strings.HasSuffix(after.UpstreamURL, wantQuery) {
		t.Fatalf("upstreamURL = %q, want suffix %q", after.UpstreamURL, wantQuery)
	}
	// A second request exercising only the copies also resolves identically.
	roundTripResolve(t, saved, "GET", "/p?old=1")
}
