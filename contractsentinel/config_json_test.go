package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// Marshal a config parsed through the standard entry point and resolve the
// same request against the original and the saved-and-reparsed config. The
// fix is that queryTransforms used to be tagged json:"-", so saving silently
// dropped every rule and a re-read stopped rewriting the query string.
func roundTripResolve(t *testing.T, cfg *Config, method, target string) (*Resolution, *Config) {
	t.Helper()
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	saved, f := ParseConfig(out)
	if f != nil {
		t.Fatalf("saved config rejected on re-read: %v\n%s", f, out)
	}
	before := resolveJSON(t, cfg, `{"method":"`+method+`","target":"`+target+`"}`)
	after := resolveJSON(t, saved, `{"method":"`+method+`","target":"`+target+`"}`)
	if before.RouteID != after.RouteID || before.UpstreamURL != after.UpstreamURL {
		t.Fatalf("resolve changed after save/reload:\n before %+v\n after  %+v", before, after)
	}
	return after, saved
}

func TestConfigMarshalPreservesQueryTransforms(t *testing.T) {
	// Literal rule fields carry spaces, Chinese, '+' and raw '%'; they must
	// be saved as literal strings, never query-encoded or -decoded.
	src := `{"routes":[
	  {"id":"plain","methods":["get"],"pathPrefix":"/a","upstream":"http://h1.example/base/"},
	  {"id":"rich","methods":["GET","POST"],"pathPrefix":"/c","upstream":"http://h3.example/u",
	   "queryTransforms":[
	     {"op":"rename","name":"x","to":"b"},
	     {"op":"set","name":"b","value":"9"},
	     {"op":"rename","name":"a b","to":"中 文+"},
	     {"op":"set","name":"%","value":"p c+%25"},
	     {"op":"set","name":"dup","value":""},
	     {"op":"remove","name":"flag"}
	   ]}
	]}`
	cfg := mustConfig(t, src)
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(out)

	// Rules are present, in order, with their literal strings.
	wantSequence := `"queryTransforms":[` +
		`{"op":"rename","name":"x","to":"b"},` +
		`{"op":"set","name":"b","value":"9"},` +
		`{"op":"rename","name":"a b","to":"中 文+"},` +
		`{"op":"set","name":"%","value":"p c+%25"},` +
		`{"op":"set","name":"dup","value":""},` +
		`{"op":"remove","name":"flag"}]`
	if !strings.Contains(doc, wantSequence) {
		t.Fatalf("rules not preserved verbatim and in order:\n%s", doc)
	}
	// remove must not carry value; rename must not carry value; set keeps the
	// empty value. No null may appear anywhere (routes or rules).
	if strings.Contains(doc, `"op":"remove","name":"flag","value"`) ||
		strings.Contains(doc, `"op":"rename","name":"x","to":"b","value"`) {
		t.Fatalf("op-specific field rules violated:\n%s", doc)
	}
	if strings.Contains(doc, "null") {
		t.Fatalf("saved config contains null:\n%s", doc)
	}
	// Basic fields keep their literal spelling: method case, upstream slash.
	if !strings.Contains(doc, `"methods":["get"]`) ||
		!strings.Contains(doc, `"upstream":"http://h1.example/base/"`) {
		t.Fatalf("basic fields not preserved:\n%s", doc)
	}

	// Duplicate params, empty values, raw percent escapes, a chained
	// rename-into-an-existing-name followed by set, and untouched fragments
	// must resolve identically before and after the save.
	target := "/c?keep=1&x=7&b=2&a+b=q&%25=raw&dup=1&dup=2&flag&keep=2&e="
	after, saved := roundTripResolve(t, cfg, "GET", target)
	if after.RouteID != "rich" {
		t.Fatalf("routeId = %q, want rich", after.RouteID)
	}
	// Sanity-check the rewritten query itself: x renames onto the existing b
	// and set merges both into one b=9 at x's position; dup collapses to an
	// empty value; flag is gone; the rest keeps order and bytes.
	wantQuery := "?keep=1&b=9&%E4%B8%AD%20%E6%96%87%2B=q&%25=p%20c%2B%2525&dup=&keep=2&e="
	if !strings.HasSuffix(after.UpstreamURL, wantQuery) {
		t.Fatalf("upstreamURL = %q, want suffix %q", after.UpstreamURL, wantQuery)
	}

	// Route order and the rules' execution order are unchanged: a second
	// request that only exercises later rules also resolves identically.
	roundTripResolve(t, saved, "POST", "/c?flag&dup=z")
	roundTripResolve(t, cfg, "get", "/a/x?untouched=a%41+%25")
}

func TestConfigMarshalRulesFieldShape(t *testing.T) {
	// Every rule re-reads with exactly the fields the input grammar allows.
	cfg := mustConfig(t, `{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h",
	  "queryTransforms":[
	    {"op":"set","name":"a","value":""},
	    {"op":"remove","name":"b"},
	    {"op":"rename","name":"c","to":"d"}
	  ]}]}`)
	var doc struct {
		Routes []struct {
			Rules []map[string]json.RawMessage `json:"queryTransforms"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(mustMarshal(t, cfg), &doc); err != nil {
		t.Fatal(err)
	}
	wantKeys := []map[string]bool{
		{"op": true, "name": true, "value": true}, // set keeps value even when empty
		{"op": true, "name": true},                // remove: no value, no to
		{"op": true, "name": true, "to": true},    // rename: to, no value
	}
	for i, rule := range doc.Routes[0].Rules {
		if len(rule) != len(wantKeys[i]) {
			t.Fatalf("rule %d keys = %v, want %v", i, keysOf(rule), wantKeys[i])
		}
		for k := range wantKeys[i] {
			if _, ok := rule[k]; !ok {
				t.Fatalf("rule %d missing key %q: %v", i, k, rule)
			}
		}
	}
}

func TestConfigMarshalWithoutRulesOrRoutes(t *testing.T) {
	// A route with no field and one with an explicit [] both save without a
	// queryTransforms key (never null), and stay readable.
	cfg := mustConfig(t, `{"routes":[
	  {"id":"absent","methods":["*"],"pathPrefix":"/a","upstream":"http://h"},
	  {"id":"empty","methods":["*"],"pathPrefix":"/b","upstream":"http://h","queryTransforms":[]}
	]}`)
	doc := string(mustMarshal(t, cfg))
	if strings.Contains(doc, "queryTransforms") || strings.Contains(doc, "null") {
		t.Fatalf("ruleless routes must omit the field without null:\n%s", doc)
	}
	roundTripResolve(t, cfg, "GET", "/a?a=1&b=")
	roundTripResolve(t, cfg, "GET", "/b?%41=1&A=2")

	// An empty route array must save as [] rather than the rejected null.
	empty := mustConfig(t, `{"routes":[]}`)
	if got := string(mustMarshal(t, empty)); got != `{"routes":[]}` {
		t.Fatalf("empty config = %s", got)
	}

	// A nil Config (never parsed, but a plain json.Marshal call) likewise
	// must not emit null.
	var nilCfg Config
	if got := string(mustMarshal(t, &nilCfg)); got != `{"routes":[]}` {
		t.Fatalf("nil config = %s", got)
	}
}

func TestConfigMarshalIndentedStillResolves(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r","methods":["get"],"pathPrefix":"/p","upstream":"http://h/b",
	  "queryTransforms":[{"op":"set","name":"q","value":"中文 +%"}]}]}`)
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	saved := mustConfig(t, string(out)) // indentation and key layout may vary
	after := resolveJSON(t, saved, `{"method":"get","target":"/p/x?q=old"}`)
	if after.RouteID != "r" || after.UpstreamURL != "http://h/b/x?q=%E4%B8%AD%E6%96%87%20%2B%25" {
		t.Fatalf("indented round trip = %+v", after)
	}
}

func TestInvalidConfigsRemainRejectedAfterMarshalCode(t *testing.T) {
	// The save path must not change read-side validation.
	for _, src := range []string{
		`{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h","queryTransforms":null}]}`,
		`{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h","queryTransforms":[{"op":"remove","name":"a","value":"x"}]}]}`,
		`{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h","queryTransforms":[{"op":"rename","name":"a","value":"x","to":"b"}]}]}`,
		`{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h","queryTransforms":[{"op":"rename","name":"a","to":""}]}]}`,
		`{"routes":null}`,
	} {
		if _, f := ParseConfig([]byte(src)); f == nil || f.Code != "invalid_config" {
			t.Fatalf("expected invalid_config for %s, got %v", src, f)
		}
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
