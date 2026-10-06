package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests pin the read-side rule that aligns pathPrefix with the request
// target: a prefix may not carry, after JSON decoding, a byte the target
// itself is forbidden from carrying — a direct ASCII space (U+0020), a C0
// control byte (U+0000 through U+001F) or DEL (U+007F). Such a route could
// never be hit by a legal request, so the whole configuration is rejected as
// invalid_config while it is read, before any request exists. Percent
// encoding is the boundary: "%20", "%09", "%00" and "%7F" are ordinary path
// text matched on the raw encoded form, and non-ASCII content such as Chinese
// is not widened into the rule.

// prefixConfigJSON builds one config document from the already-decoded
// prefix string, so JSON escapes such as "\n", "\t" and " " are emitted
// exactly the way a configuration file would carry them.
func prefixConfigJSON(t *testing.T, id, prefix, upstream string) []byte {
	t.Helper()
	doc := struct {
		Routes []struct {
			ID         string   `json:"id"`
			Methods    []string `json:"methods"`
			PathPrefix string   `json:"pathPrefix"`
			Upstream   string   `json:"upstream"`
		} `json:"routes"`
	}{}
	doc.Routes = append(doc.Routes, struct {
		ID         string   `json:"id"`
		Methods    []string `json:"methods"`
		PathPrefix string   `json:"pathPrefix"`
		Upstream   string   `json:"upstream"`
	}{id, []string{"GET"}, prefix, upstream})
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return b
}

// TestInvalidConfigPrefixDirectControlCharacters pins the direct-character
// rule on pathPrefix: after JSON decoding, a space, a C0 control byte
// (U+0000..U+001F) or DEL (U+007F) appearing literally anywhere in the
// prefix rejects the whole configuration, regardless of route order or of
// which route a request would hit. The reason names pathPrefix, the route's
// 1-based position, the route's valid non-empty id and the first offending
// byte as U+XXXX, and no config is handed back.
func TestInvalidConfigPrefixDirectControlCharacters(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		want   string // U+XXXX token for the first offending character
	}{
		{"space inside a path segment", "/api/orders next", "U+0020"},
		{"space right after the leading slash", "/ api", "U+0020"},
		{"trailing space", "/api/orders ", "U+0020"},
		{"newline after a prefix", "/api/orders\n", "U+000A"},
		{"carriage return in the prefix", "/api/orders\r", "U+000D"},
		{"tab in the prefix", "/api/orders\t/x", "U+0009"},
		{"null byte in the prefix", "/api/orders\x00/x", "U+0000"},
		{"start of heading byte", "/a\x01b", "U+0001"},
		{"end of transmission byte", "/x\x04", "U+0004"},
		{"unit separator byte", "/x\x1fy", "U+001F"},
		{"delete byte in the prefix", "/x\x7f", "U+007F"},
		{"first offender is the earlier space, not the later newline", "/a b\nc", "U+0020"},
		{"first offender is a newline earlier than a later space", "/a\nb c", "U+000A"},
		{"first offender is the null byte at the front", "/\x00a b", "U+0000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := prefixConfigJSON(t, "orders", tc.prefix, "http://h.internal")
			cfg, f := ParseConfig(src)
			if f == nil {
				t.Fatalf("ParseConfig(%q): expected invalid_config", tc.prefix)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			for _, want := range []string{"pathPrefix", "route 1", `"orders"`, tc.want} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("a direct character is a content error, not a JSON syntax failure: %q", f.Reason)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
		})
	}

	// The offending route may follow a perfectly usable route and may be one
	// the current request never hits: the read still fails up front and hands
	// back no config at all, so the earlier route can never resolve.
	cfg, f := ParseConfig([]byte(`{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin area","upstream":"http://admin.internal"}
	]}`))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("unhit later route with a spaced prefix: got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	for _, want := range []string{"route 2", `"admin"`, "pathPrefix", "U+0020"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}
}

// TestInvalidConfigPrefixJSONEscapesDecodedThenRejected proves the rule
// operates on the decoded prefix: a literal space and a " " escape decode to
// the same byte and fail identically, while "\n", "\t", "\r", "\u0000" and
// "\u007F" cannot bypass the check either. The rule is content validation,
// never a JSON parse failure.
func TestInvalidConfigPrefixJSONEscapesDecodedThenRejected(t *testing.T) {
	cases := []struct {
		name    string
		jsonDoc string
		want    string
	}{
		{"json unicode escape for space", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\u0020b","upstream":"http://h"}]}`, "U+0020"},
		{"json newline escape", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\n","upstream":"http://h"}]}`, "U+000A"},
		{"json tab escape", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\tb","upstream":"http://h"}]}`, "U+0009"},
		{"json carriage return escape", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\rb","upstream":"http://h"}]}`, "U+000D"},
		{"json null escape", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\u0000b","upstream":"http://h"}]}`, "U+0000"},
		{"json lowercase unicode escape for del", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\u007f","upstream":"http://h"}]}`, "U+007F"},
		{"a literal space fails the same way as the escape", `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"}]}`, "U+0020"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, f := ParseConfig([]byte(tc.jsonDoc))
			if f == nil || f.Code != "invalid_config" {
				t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
			}
			for _, want := range []string{"pathPrefix", "route 1", `"r"`, tc.want} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("a decoded control byte is a content error, not a JSON syntax failure: %q", f.Reason)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned")
			}
		})
	}

	// The decoded-vs-raw equivalence is also observable through
	// encoding/json: a literal space and a " " escape unmarshal to the
	// same prefix string, and ParseConfig rejects both.
	for _, spelled := range []string{
		`{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"}]}`,
		`{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a\u0020b","upstream":"http://h"}]}`,
	} {
		var doc struct {
			Routes []struct {
				PathPrefix string `json:"pathPrefix"`
			} `json:"routes"`
		}
		if err := json.Unmarshal([]byte(spelled), &doc); err != nil {
			t.Fatal(err)
		}
		if got := doc.Routes[0].PathPrefix; got != "/a b" {
			t.Fatalf("decoded prefix = %q, want /a b", got)
		}
	}
}

// TestInvalidConfigPrefixCharacterPrecedence pins the error-selection order
// for the new content rule: JSON syntax, structure and basic field types,
// then queryTransforms rule errors are all still reported first — even on
// later routes — while among route content errors the earliest route in the
// array wins, and within one route the existing prefix checks keep their
// order (a malformed percent escape or a fragment still beats the direct
// character later in the same prefix).
func TestInvalidConfigPrefixCharacterPrecedence(t *testing.T) {
	// Layer 1: broken JSON beats a spaced prefix.
	expectInvalidConfig(t, `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"} BROKEN`,
		[]string{"not valid JSON"},
		[]string{"U+0020", "pathPrefix"})

	// Layer 2: a field type error on a later route beats a spaced prefix on
	// route 1.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"early","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"},
	  {"id":"later","methods":"GET","pathPrefix":"/b","upstream":"http://h2"}
	]}`,
		[]string{"route 2", `"later"`, "methods must be an array of strings"},
		[]string{"U+0020", "route 1"})

	// Layer 3: an illegal query rule on a later route beats a spaced prefix
	// on route 1.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"early","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"},
	  {"id":"later","methods":["GET"],"pathPrefix":"/b","upstream":"http://h2",
	   "queryTransforms":[{"op":"frob","name":"x"}]}
	]}`,
		[]string{"route 2", `"later"`, "queryTransforms rule 1", "unknown op"},
		[]string{"U+0020", "route 1"})

	// Layer 4, earliest route: two offending prefixes report route 1 no
	// matter which byte is "worse".
	expectInvalidConfig(t, `{"routes":[
	  {"id":"a","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"},
	  {"id":"b","methods":["GET"],"pathPrefix":"/b\u0000c","upstream":"http://h2"}
	]}`,
		[]string{"route 1", `"a"`, "U+0020"},
		[]string{"route 2", "U+0000"})

	// And a content error of an earlier kind still beats the character rule
	// on a later route: route 1's bad method token is reported first.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"a","methods":["GE T"],"pathPrefix":"/a","upstream":"http://h"},
	  {"id":"b","methods":["GET"],"pathPrefix":"/b c","upstream":"http://h2"}
	]}`,
		[]string{"route 1", `"a"`, "invalid method"},
		[]string{"route 2", "U+0020"})

	// Within one prefix, a malformed percent escape keeps its earlier reason
	// over the direct newline behind it, as on the request side.
	for _, src := range []string{
		`{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a%zz\n","upstream":"http://h"}]}`,
		`{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a%2\n","upstream":"http://h"}]}`,
	} {
		expectInvalidConfig(t, src,
			[]string{"pathPrefix", "percent escape"},
			[]string{"U+000A"})
	}

	// The fragment/query check precedes the direct character after the '#'.
	expectInvalidConfig(t, `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/a#f\n","upstream":"http://h"}]}`,
		[]string{"query string or fragment"},
		[]string{"U+000A"})
}

// TestConfigPrefixPercentEncodedControlCharactersUnaffected pins the other
// half of the rule at the config and resolve boundary: percent-encoded bytes
// are not direct characters. A prefix such as /a%20b stays a legal
// configuration and matches /a%20b/items on the raw encoded spelling; "%09",
// "%00" and "%7F" keep working as raw text too, the escape case and segment
// boundaries are preserved, and the encoded bytes reach upstreamURL byte for
// byte with no decoding or re-encoding.
func TestConfigPrefixPercentEncodedControlCharactersUnaffected(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"spaced","methods":["GET"],"pathPrefix":"/a%20b","upstream":"http://spaced.internal/s"},
	  {"id":"ctrl","methods":["GET"],"pathPrefix":"/t%09x%00","upstream":"http://ctrl.internal/c"},
	  {"id":"lower","methods":["GET"],"pathPrefix":"/a%2fb","upstream":"http://lower.internal/l"},
	  {"id":"cn","methods":["*"],"pathPrefix":"/中文","upstream":"http://cn.internal/中"}
	]}`)
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "encoded space prefix matches the encoded request",
			target:   "/a%20b/items",
			routeID:  "spaced",
			upstream: "http://spaced.internal/s/items",
		},
		{
			name:     "exact encoded prefix keeps one junction slash",
			target:   "/a%20b",
			routeID:  "spaced",
			upstream: "http://spaced.internal/s/",
		},
		{
			name:     "encoded tab and null in a prefix match raw",
			target:   "/t%09x%00/y",
			routeID:  "ctrl",
			upstream: "http://ctrl.internal/c/y",
		},
		{
			name:     "uppercase %2F in the prefix keeps its case and is a segment, not a slash",
			target:   "/a%2fb/x",
			routeID:  "lower",
			upstream: "http://lower.internal/l/x",
		},
		{
			name:     "chinese prefix and chinese remainder are unaffected",
			target:   "/中文/订单",
			routeID:  "cn",
			upstream: "http://cn.internal/中/订单",
		},
	}

	// An encoded slash directly after the prefix keeps the segment going:
	// /a%20b is not a boundary hit for /a%20b%2Fcontinue, so without a
	// shorter matching prefix the request is route_not_found, exactly as for
	// any raw prefix.
	if _, rf := Resolve(cfg, mustReq(t, "GET", "/a%20b%2Fcontinue")); rf == nil || rf.Code != "route_not_found" {
		t.Fatalf("got %+v, want route_not_found (%%2F continues the segment)", rf)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", res.RouteID, tc.routeID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}

	// A request carrying a literal space is invalid_request on its own
	// merits, so it can never hit the encoded-space route; the encoded
	// route never serves a decoded spelling.
	_, rf := ParseRequest(requestJSONString(t, "GET", "/a b/items"))
	if rf == nil || rf.Code != "invalid_request" {
		t.Fatalf("request with a literal-space target: got %+v, want invalid_request", rf)
	}
	res, f := Resolve(cfg, &Request{Method: "GET", Target: "/a b/items"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("literal-space target: got res=%+v f=%+v, want invalid_request only", res, f)
	}

	// A request whose path spells the prefix with a decoded space does not
	// match the encoded route: with a root fallback it falls through to it.
	withFallback := mustConfig(t, `{"routes":[
	  {"id":"spaced","methods":["GET"],"pathPrefix":"/a%20b","upstream":"http://spaced.internal/s"},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://fallback.internal/base"}
	]}`)
	// The only legal way to send a space in the target is encoded; a request
	// to a different encoded spelling must not match /a%20b either.
	res = resolveJSON(t, withFallback, `{"method":"GET","target":"/a%2fb/x"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root (different raw spelling)", res.RouteID)
	}

	// A U+00A0 (non-ASCII whitespace) prefix byte is outside the forbidden
	// ASCII set: the config stays valid and the byte is carried verbatim.
	nbsp := mustConfig(t, `{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/a\u00a0b","upstream":"http://h.internal/base"}]}`)
	req, rf := ParseRequest(requestJSONString(t, "GET", "/a\u00a0b/x"))
	if rf != nil {
		t.Fatalf("U+00A0 request must stay valid: %+v", rf)
	}
	got, rf := Resolve(nbsp, req)
	if rf != nil {
		t.Fatalf("U+00A0 prefix must stay usable: %+v", rf)
	}
	if got.RouteID != "r" || got.UpstreamURL != "http://h.internal/base/x" {
		t.Fatalf("U+00A0 prefix resolution = %+v", got)
	}
}

// TestConfigPrefixCharacterRuleRoundTrip pins that saving and re-reading a
// legal config keeps the encoded prefix byte for byte, while a Route value
// carrying a decoded forbidden byte can never have come from ParseConfig in
// the first place: the rejection happens at read time and no prefix is
// trimmed or re-encoded to make it legal.
func TestConfigPrefixCharacterRuleRoundTrip(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"spaced","methods":["GET"],"pathPrefix":"/a%20b","upstream":"http://spaced.internal/s"}
	]}`)
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"/a%20b"`) {
		t.Fatalf("encoded prefix must be saved byte for byte:\n%s", out)
	}
	saved := mustConfig(t, string(out))
	res := resolveJSON(t, saved, `{"method":"GET","target":"/a%20b/items"}`)
	if res.RouteID != "spaced" || res.UpstreamURL != "http://spaced.internal/s/items" {
		t.Fatalf("reloaded config resolution = %+v", res)
	}

	// Constructing a Route in-process with a forbidden prefix and marshalling
	// it does not launder the byte: the saved document carries the JSON
	// escape for the literal space, and re-reading rejects it with the same
	// content error — nothing deleted, trimmed or percent-encoded away.
	direct := &Config{Routes: []Route{{
		ID: "direct", Methods: []string{"GET"}, PathPrefix: "/a b", Upstream: "http://h",
	}}}
	raw, err := json.Marshal(direct)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"/a b"`) {
		t.Fatalf("marshal must preserve the literal space as a JSON string:\n%s", raw)
	}
	if _, f := ParseConfig(raw); f == nil || f.Code != "invalid_config" {
		t.Fatalf("re-reading a literal-space prefix: got %+v, want invalid_config", f)
	}
}
