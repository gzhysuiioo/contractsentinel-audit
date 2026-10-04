package contractsentinel

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// TestConfigMarshalKeepsQueryTransforms is the headline fix: a config that
// ParseConfig accepted used to serialize without its queryTransforms (the
// field was tagged json:"-"), so reparsing the saved file silently dropped
// every rewrite rule. The serialized document must keep every route's basic
// fields and every rule, in route and rule order.
func TestConfigMarshalKeepsQueryTransforms(t *testing.T) {
	src := `{
  "routes": [
    {"id":"first","methods":["get","POST"],"pathPrefix":"/a%20b","upstream":"http://one.internal/base/",
     "queryTransforms":[
       {"op":"rename","name":"old","to":"new"},
       {"op":"remove","name":"flag"},
       {"op":"set","name":"a&b=c","value":""}
     ]},
    {"id":"second","methods":["*"],"pathPrefix":"/x","upstream":"https://two.internal:8443/u"},
    {"id":"third","methods":["GET"],"pathPrefix":"/y","upstream":"http://three.internal",
     "queryTransforms":[{"op":"set","name":"k","value":"v"}]}
  ]
}`
	cfg := mustConfig(t, src)

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc struct {
		Routes []struct {
			ID              string            `json:"id"`
			Methods         []string          `json:"methods"`
			PathPrefix      string            `json:"pathPrefix"`
			Upstream        string            `json:"upstream"`
			QueryTransforms []json.RawMessage `json:"queryTransforms"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("marshaled config is not valid JSON: %v\n%s", err, out)
	}
	if len(doc.Routes) != 3 {
		t.Fatalf("route count = %d, want 3; json: %s", len(doc.Routes), out)
	}
	first := doc.Routes[0]
	if first.ID != "first" || !reflect.DeepEqual(first.Methods, []string{"get", "POST"}) ||
		first.PathPrefix != "/a%20b" || first.Upstream != "http://one.internal/base/" {
		t.Fatalf("basic fields changed after marshal: %+v", first)
	}
	if len(first.QueryTransforms) != 3 {
		t.Fatalf("first route rules = %d, want 3: %s", len(first.QueryTransforms), out)
	}
	if doc.Routes[1].QueryTransforms != nil {
		t.Fatalf("a route without rules must omit the field or emit an empty array, got %s",
			doc.Routes[1].QueryTransforms)
	}
	if len(doc.Routes[2].QueryTransforms) != 1 {
		t.Fatalf("third route rules = %d, want 1", len(doc.Routes[2].QueryTransforms))
	}

	// Rule order must survive; decode each rule in the serialized order.
	type rule struct {
		Op    string `json:"op"`
		Name  string `json:"name"`
		Value string `json:"value"`
		To    string `json:"to"`
	}
	var rules []rule
	for _, raw := range first.QueryTransforms {
		var r rule
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("rule %s is not valid JSON: %v", raw, err)
		}
		rules = append(rules, r)
	}
	wantRules := []rule{
		{Op: "rename", Name: "old", To: "new"},
		{Op: "remove", Name: "flag"},
		{Op: "set", Name: "a&b=c", Value: ""},
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("rules in order = %+v, want %+v", rules, wantRules)
	}
}

// TestMarshalQueryTransformRuleShapes pins the per-op output contract: the
// saved rules must satisfy the same field restrictions the reader enforces.
func TestMarshalQueryTransformRuleShapes(t *testing.T) {
	cases := []struct {
		name     string
		rule     *QueryTransform
		wantKeys map[string]bool
	}{
		{
			name:     "set keeps value, even when empty",
			rule:     &QueryTransform{Op: "set", Name: "a", Value: ""},
			wantKeys: map[string]bool{"op": true, "name": true, "value": true},
		},
		{
			name:     "set with a value keeps value",
			rule:     &QueryTransform{Op: "set", Name: "a", Value: "x=y"},
			wantKeys: map[string]bool{"op": true, "name": true, "value": true},
		},
		{
			name:     "remove emits no value",
			rule:     &QueryTransform{Op: "remove", Name: "a", Value: "should be ignored"},
			wantKeys: map[string]bool{"op": true, "name": true},
		},
		{
			name:     "rename keeps to and emits no value",
			rule:     &QueryTransform{Op: "rename", Name: "a", To: "b", Value: "should be ignored"},
			wantKeys: map[string]bool{"op": true, "name": true, "to": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.rule)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(out, &fields); err != nil {
				t.Fatalf("rule output is not a JSON object: %v\n%s", err, out)
			}
			if len(fields) != len(tc.wantKeys) {
				t.Fatalf("keys = %v, want %v; json: %s", keysOf(fields), tc.wantKeys, out)
			}
			for k := range tc.wantKeys {
				if _, ok := fields[k]; !ok {
					t.Fatalf("missing key %q in %s", k, out)
				}
			}
			if _, ok := fields["value"]; ok && tc.rule.Op != "set" {
				t.Fatalf("%s must not emit value: %s", tc.rule.Op, out)
			}
			if tc.rule.Op == "set" {
				var v string
				if err := json.Unmarshal(fields["value"], &v); err != nil {
					t.Fatalf("value is not a JSON string: %v", err)
				}
				if v != tc.rule.Value {
					t.Fatalf("value = %q, want %q", v, tc.rule.Value)
				}
			}

			// The serialized rule must be accepted on its own through the
			// existing reader, wrapped in one route.
			src := `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h",` +
				`"queryTransforms":[` + string(out) + `]}]}`
			if _, f := ParseConfig([]byte(src)); f != nil {
				t.Fatalf("marshaled rule must be accepted by ParseConfig: %v\njson: %s", f, out)
			}
		})
	}
}

// TestMarshalQueryTransformKeepsLiteralStrings ensures name/value/to are
// saved as the literal decoded strings: JSON string escaping is the only
// transform applied, so spaces, Chinese, '+' and '%' are not query
// percent-encoded or decoded and match the same parameters after reparse.
func TestMarshalQueryTransformKeepsLiteralStrings(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h","queryTransforms":[
	  {"op":"rename","name":"a+b 名%","to":"c+d 字%"},
	  {"op":"set","name":"a&b=c","value":"空格 中文+%2f%25"},
	  {"op":"remove","name":"x+y%20z"}
	]}]}`)
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reparsed, f := ParseConfig(out)
	if f != nil {
		t.Fatalf("reparse: %v\n%s", f, out)
	}
	got := reparsed.Routes[0].QueryTransforms
	want := cfg.Routes[0].QueryTransforms
	if len(got) != len(want) {
		t.Fatalf("rule count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Op != want[i].Op || got[i].Name != want[i].Name ||
			got[i].Value != want[i].Value || got[i].To != want[i].To {
			t.Fatalf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Spot-check the literal bytes are not query-escaped in the JSON text.
	for _, literal := range []string{"a+b 名%", "c+d 字%", "空格 中文+%2f%25", "x+y%20z"} {
		encoded, _ := json.Marshal(literal)
		if !bytes.Contains(out, encoded) {
			t.Errorf("serialized config must keep literal %s (JSON %s)\n%s", literal, encoded, out)
		}
	}
}

// TestConfigMarshalRoundTripPreservesResolution is the end-to-end contract:
// resolving the same requests against the parsed config and the
// marshal-then-reparse config must yield the same routeId and
// upstreamURL, including duplicate names, empty values, raw percent
// escapes, empty fragments and chained rename/set/remove rules.
func TestConfigMarshalRoundTripPreservesResolution(t *testing.T) {
	src := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1",
	   "queryTransforms":[
	     {"op":"rename","name":"old","to":"mid"},
	     {"op":"rename","name":"mid","to":"new"},
	     {"op":"set","name":"new","value":""},
	     {"op":"remove","name":"flag"}
	   ]},
	  {"id":"plain","methods":["POST"],"pathPrefix":"/plain","upstream":"http://plain.internal"},
	  {"id":"empty","methods":["*"],"pathPrefix":"/e","upstream":"http://e.internal","queryTransforms":[]}
	]}`
	cfg := mustConfig(t, src)

	// Both compact and indented forms are supported serializations.
	for _, marshal := range []func(any) ([]byte, error){
		json.Marshal,
		func(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") },
	} {
		out, err := marshal(cfg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reparsed, cf := ParseConfig(out)
		if cf != nil {
			t.Fatalf("saved config must be accepted by ParseConfig: %v\n%s", cf, out)
		}
		// The empty-array route may omit the field, but it must never be
		// written as null, which the reader rejects.
		if bytes.Contains(out, []byte(`"queryTransforms":null`)) {
			t.Fatalf("queryTransforms must not be serialized as null:\n%s", out)
		}

		targets := []string{
			`{"method":"GET","target":"/api/p?old=1&old=2&new=9&a=&a=2&b=%41%2f&flag"}`,
			`{"method":"GET","target":"/api/p?mid=0&&old=x&"}`,
			`{"method":"GET","target":"/api?"}`,
			`{"method":"GET","target":"/api"}`,
			`{"method":"POST","target":"/plain/z?keep=1&keep=2&q=%2f+"}`,
			`{"method":"GET","target":"/e?a=1&b="}`,
		}
		for _, reqSrc := range targets {
			req, rf := ParseRequest([]byte(reqSrc))
			if rf != nil {
				t.Fatalf("bad request %q: %v", reqSrc, rf)
			}
			got, gErr := Resolve(reparsed, req)
			req2, _ := ParseRequest([]byte(reqSrc))
			want, wErr := Resolve(cfg, req2)
			switch {
			case (gErr == nil) != (wErr == nil):
				t.Fatalf("resolve presence differs for %s:\n%+v\n%+v", reqSrc, got, gErr)
			case gErr != nil && (gErr.Code != wErr.Code || gErr.Reason != wErr.Reason):
				t.Fatalf("resolve error differs for %s:\n%v\n%v", reqSrc, gErr, wErr)
			case gErr == nil && (got.RouteID != want.RouteID || got.UpstreamURL != want.UpstreamURL):
				t.Fatalf("resolve differs for %s:\n%s %s\n%s %s",
					reqSrc, got.RouteID, got.UpstreamURL, want.RouteID, want.UpstreamURL)
			}
		}
	}
}

// TestConfigMarshalOmitsQueryTransformsWithoutNull checks both ways a route
// may lack rules (absent field and an explicit empty array): the saved JSON
// must parse again and must never emit a null queryTransforms.
func TestConfigMarshalOmitsQueryTransformsWithoutNull(t *testing.T) {
	for _, field := range []string{``, `,"queryTransforms":[]`} {
		src := `{"routes":[{"id":"r1","methods":["*"],"pathPrefix":"/","upstream":"http://h"` + field + `}]}`
		cfg := mustConfig(t, src)
		out, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if bytes.Contains(out, []byte("null")) {
			t.Fatalf("config without rules must not serialize null: %s", out)
		}
		reparsed, f := ParseConfig(out)
		if f != nil {
			t.Fatalf("reparse: %v\n%s", f, out)
		}
		if reparsed.Routes[0].QueryTransforms != nil {
			t.Fatalf("reparsed rules = %v, want none", reparsed.Routes[0].QueryTransforms)
		}
		// A request query is still preserved verbatim.
		res := resolveJSON(t, reparsed, `{"method":"GET","target":"/p?a=1&a=&b=%2f"}`)
		if want := "http://h/p?a=1&a=&b=%2f"; res.UpstreamURL != want {
			t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
