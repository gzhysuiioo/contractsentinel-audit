package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// prefixJSONString encodes one already-decoded prefix as a JSON string
// value, so literal bytes and JSON escapes such as "\n" and " " are
// emitted exactly the way a configuration file would carry them.
func prefixJSONString(t *testing.T, prefix string) string {
	t.Helper()
	b, err := json.Marshal(prefix)
	if err != nil {
		t.Fatalf("marshal pathPrefix: %v", err)
	}
	return string(b)
}

// This file pins the direct-character rule for a configured pathPrefix: a
// prefix that otherwise satisfies the prefix format is still rejected when
// the decoded string carries a direct ASCII space (U+0020), a C0 control
// byte (U+0000..U+001F) or DEL (U+007F), because a request target may not
// carry that byte directly either, so such a route could never be hit by a
// legal request. The whole configuration fails as invalid_config while it
// is read — even when the offending route follows a route the request would
// hit — and no config is handed back. Percent-encoded bytes ("%20", "%09",
// "%00", ...) stay legal raw text and keep matching byte for byte.

// prefixCharConfig builds one two-route document whose second route carries
// the given raw pathPrefix text (already JSON-encoded by the caller when it
// contains escapes); route 1 is an ordinary /api route every legal request
// in these tests could hit instead.
func prefixCharConfig(secondPrefixJSON string) string {
	return `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"bad","methods":["GET"],"pathPrefix":` + secondPrefixJSON + `,"upstream":"http://bad.internal"}
	]}`
}

// TestConfigPrefixDirectControlCharactersRejected pins the direct-character
// rule for pathPrefix: a literal space, C0 control byte or DEL appearing
// directly in an otherwise well-formed prefix invalidates the whole
// document, and the reason names pathPrefix, the route's 1-based position,
// its valid non-empty id and the first offending character as U+XXXX.
func TestConfigPrefixDirectControlCharactersRejected(t *testing.T) {
	cases := []struct {
		name   string
		prefix string // decoded Go string; marshaled to JSON by the test
		want   string // U+XXXX token for the first offending character
	}{
		{"space inside a segment", "/a b", "U+0020"},
		{"leading space after the slash", "/ b", "U+0020"},
		{"trailing space", "/ab ", "U+0020"},
		{"newline in the prefix", "/a\nb", "U+000A"},
		{"carriage return in the prefix", "/a\rb", "U+000D"},
		{"tab in the prefix", "/a\tb", "U+0009"},
		{"null byte in the prefix", "/a\x00b", "U+0000"},
		{"end of transmission byte", "/a\x04b", "U+0004"},
		{"delete byte", "/a\x7fb", "U+007F"},
		{"first offender is the earlier space, not the later newline", "/a b\nc", "U+0020"},
		{"first offender is a newline earlier than a later space", "/a\nb c", "U+000A"},
		{"first offender is the null byte at the front", "/\x00a b", "U+0000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := prefixJSONString(t, tc.prefix)
			src := prefixCharConfig(raw)
			cfg, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("ParseConfig(%q): expected invalid_config", tc.prefix)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			for _, want := range []string{"route 2", `"bad"`, "pathPrefix", tc.want} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("a direct prefix byte is a content error, not a JSON syntax failure: %q", f.Reason)
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
		})
	}
}

// TestConfigPrefixJSONEscapesDecodedThenRejected proves the rule operates on
// the decoded prefix: writing the byte literally and spelling it as a JSON
// string escape ("\n", "\t", a backslash-u space escape, "\u0000",
// "\u007F") are the same configuration once decoded and fail the same way.
func TestConfigPrefixJSONEscapesDecodedThenRejected(t *testing.T) {
	literal := prefixCharConfig(`"/a b"`)
	// Split the backslash-u escape token so it stays literal text; when
	// concatenated it is the JSON spelling "/a<backslash>u0020b".
	escaped := prefixCharConfig(`"/a\u00` + `20b"`)
	for name, src := range map[string]string{
		"literal space":        literal,
		"unicode space":        escaped,
		"json newline":         prefixCharConfig(`"/a\nb"`),
		"json tab":             prefixCharConfig(`"/a\tb"`),
		"json carriage return": prefixCharConfig(`"/a\rb"`),
		"json null escape":     prefixCharConfig(`"/a\u0000b"`),
		"json del escape":      prefixCharConfig(`"/a\u007fb"`),
		"uppercase del escape": prefixCharConfig(`"/a\u007Fb"`),
	} {
		t.Run(name, func(t *testing.T) {
			expectInvalidConfig(t, src,
				[]string{"route 2", `"bad"`, "pathPrefix"},
				[]string{"not valid JSON"})
		})
	}

	// The literal-space and escaped-space spellings must surface the exact
	// same reason, proving the check sees only the decoded string.
	_, fl := ParseConfig([]byte(literal))
	_, fe := ParseConfig([]byte(escaped))
	if fl == nil || fe == nil || fl.Reason != fe.Reason {
		t.Fatalf("literal space reason %q != unicode-escape reason %q", fl, fe)
	}
}

// TestConfigPrefixOffendingRouteRejectsWholeConfig proves the read fails up
// front even when the offending route can never be selected: it follows a
// route that serves the request, and the request is unrelated to it.
func TestConfigPrefixOffendingRouteRejectsWholeConfig(t *testing.T) {
	// A direct tab on route 2; the request that the CLI would send hits
	// route 1 only — this is checked at the ParseConfig level here and at
	// the command boundary elsewhere.
	src := prefixCharConfig(`"/admin\tarea"`)
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("unhit offending route: got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if cfg != nil {
		t.Fatalf("a rejected config must not be returned, got %+v", cfg)
	}

	// A lone offending route still fails even without any legal route
	// preceding it.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"only","methods":["GET"],"pathPrefix":"/x y","upstream":"http://h"}
	]}`, []string{"route 1", `"only"`, "pathPrefix", "U+0020"}, nil)
}

// TestConfigPrefixCharacterErrorOrdering pins where the new content error
// sits in the existing error-selection order: JSON syntax, then structure
// and basic field types, then queryTransforms rules, then field contents;
// within the content layer the routes-array position (and within a route the
// existing field order) decides.
func TestConfigPrefixCharacterErrorOrdering(t *testing.T) {
	// A broken document is only ever a parse failure, the spaced prefix is
	// never located by guessing.
	expectInvalidConfig(t, `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a b" BROKEN`,
		[]string{"not valid JSON"},
		[]string{"route 1", "pathPrefix", "U+"})

	// A field TYPE error on a later route beats the earlier route's spaced
	// prefix and even a bad queryTransforms rule on that earlier route.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"early","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h",
	   "queryTransforms":[{"op":"frob","name":"a"}]},
	  {"id":"later","methods":"GET","pathPrefix":"/b","upstream":"http://h2"}
	]}`,
		[]string{"route 2", `"later"`, "methods must be an array of strings"},
		[]string{"U+0020", "queryTransforms rule", "frob"})

	// A queryTransforms RULE error on a later route beats the earlier
	// route's spaced prefix.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"early","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"},
	  {"id":"later","methods":["GET"],"pathPrefix":"/b","upstream":"http://h2",
	   "queryTransforms":[{"op":"frob","name":"x"}]}
	]}`,
		[]string{"route 2", `"later"`, "queryTransforms rule 1", "unknown op"},
		[]string{"U+0020", "route 1"})

	// A bad rule on the SAME route still outranks that route's spaced
	// prefix.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"r1","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h",
	   "queryTransforms":[{"op":"remove","name":"a","value":"x"}]}
	]}`,
		[]string{"route 1", `"r1"`, "remove must not include a value"},
		[]string{"U+0020"})

	// Within the content layer the earliest route wins: a spaced prefix on
	// route 1 is reported before a different content error on route 2.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"r1","methods":["GET"],"pathPrefix":"/a b","upstream":"http://h"},
	  {"id":"r2","methods":["GET"],"pathPrefix":"not-abs","upstream":"http://h2"}
	]}`,
		[]string{"route 1", `"r1"`, "U+0020"},
		[]string{"route 2", "must start with /"})

	// Two spaced prefixes: the first route in the array is reported, never
	// the id lexicographic order.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"zzz","methods":["GET"],"pathPrefix":"/z z","upstream":"http://h"},
	  {"id":"aaa","methods":["GET"],"pathPrefix":"/a\ta","upstream":"http://h2"}
	]}`,
		[]string{"route 1", `"zzz"`, "U+0020"},
		[]string{`"aaa"`, "route 2", "U+0009"})

	// The existing per-route content order is kept: an invalid method token
	// is reported before the same route's spaced prefix (methods are
	// validated first).
	expectInvalidConfig(t, `{"routes":[
	  {"id":"r1","methods":["GE\tT"],"pathPrefix":"/a b","upstream":"http://h"}
	]}`,
		[]string{"route 1", `"r1"`, "invalid method"},
		[]string{"U+0020"})

	// The earlier prefix checks keep their order: a non-absolute prefix is
	// reported before its space, and a malformed percent escape before a
	// later space.
	expectInvalidConfig(t, `{"routes":[
	  {"id":"r1","methods":["GET"],"pathPrefix":"a b","upstream":"http://h"}
	]}`,
		[]string{"pathPrefix must start with /"},
		[]string{"U+"})
	expectInvalidConfig(t, `{"routes":[
	  {"id":"r1","methods":["GET"],"pathPrefix":"/a%2 b","upstream":"http://h"}
	]}`,
		[]string{"invalid percent escape"},
		[]string{"U+"})
}

// TestConfigPrefixEncodedControlCharactersAccepted pins the distinction
// between direct and percent-encoded bytes for pathPrefix: an encoded space,
// tab, newline, null or DEL is ordinary raw path content — never decoded
// before validation or matching — so a "/a%20b" route matches "/a%20b" and
// "/a%20b/items" on the raw spelling, keeps segment boundaries and joins the
// remainder the usual way. The direct byte still cannot reach such a route:
// a target carrying the decoded character directly stays invalid_request.
func TestConfigPrefixEncodedControlCharactersAccepted(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"space","methods":["GET"],"pathPrefix":"/a%20b","upstream":"http://space.internal/s"},
	  {"id":"tab","methods":["GET"],"pathPrefix":"/a%09b","upstream":"http://tab.internal/t"},
	  {"id":"null","methods":["GET"],"pathPrefix":"/a%00b","upstream":"http://null.internal/n"},
	  {"id":"root","methods":["*"],"pathPrefix":"/","upstream":"http://fallback.internal/base"}
	]}`)

	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{"encoded space prefix matches its segment", "/a%20b/items", "space", "http://space.internal/s/items"},
		{"exact encoded space prefix keeps one junction slash", "/a%20b", "space", "http://space.internal/s/"},
		{"encoded tab prefix matches", "/a%09b/x", "tab", "http://tab.internal/t/x"},
		{"encoded null prefix matches", "/a%00b", "null", "http://null.internal/n/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, string(requestJSONString(t, "GET", tc.target)))
			if res.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", res.RouteID, tc.routeID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}

	// A request that decoded the space may not be resolved at all:
	// ParseRequest rejects the direct byte before route selection, so it can
	// never hit the "%20"-spelled route (and never reaches the root either).
	req, f := ParseRequest(requestJSONString(t, "GET", "/a b/items"))
	if f == nil || f.Code != "invalid_request" {
		t.Fatalf("direct-space target: got req=%+v f=%+v, want invalid_request", req, f)
	}
	if !strings.Contains(f.Reason, "U+0020") {
		t.Fatalf("reason = %q, want U+0020", f.Reason)
	}

	// Encoded escapes are never decoded before matching: the encoded route
	// does not match a literal-space-free differently-spelled path, and a
	// differently-cased escape is a different prefix.
	res, rf := Resolve(cfg, mustReq(t, "GET", "/a%20B/items"))
	if rf != nil || res.RouteID != "root" {
		t.Fatalf("case differs: got res=%+v rf=%+v, want root fallback", res, rf)
	}
	res = resolveJSON(t, cfg, string(requestJSONString(t, "GET", "/a%2fb/x")))
	if res.RouteID != "root" {
		t.Fatalf("an unrelated encoded path must fall through to root, got %q", res.RouteID)
	}

	// An encoded space extends the segment, so a shorter real-boundary
	// prefix does not swallow it; the root route is the only candidate.
	res = resolveJSON(t, cfg, string(requestJSONString(t, "GET", "/a%20bmore/x")))
	if res.RouteID != "root" {
		t.Fatalf("encoded space is same-segment content, got route %q", res.RouteID)
	}
}

// TestConfigPrefixOtherCharactersUnaffected pins that the rule is not
// widened: Chinese characters and other Unicode content that was previously
// accepted stay accepted, match on the raw UTF-8 bytes and join unchanged,
// and non-ASCII whitespace such as U+00A0 is not an ASCII space or control
// byte.
func TestConfigPrefixOtherCharactersUnaffected(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"cn","methods":["GET"],"pathPrefix":"/订单","upstream":"http://cn.internal/c"},
	  {"id":"nbsp","methods":["GET"],"pathPrefix":"/a b","upstream":"http://nbsp.internal/n"}
	]}`)

	res := resolveJSON(t, cfg, string(requestJSONString(t, "GET", "/订单/7?note=中文")))
	if res.RouteID != "cn" {
		t.Fatalf("routeId = %q, want cn", res.RouteID)
	}
	if want := "http://cn.internal/c/7?note=中文"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	res = resolveJSON(t, cfg, string(requestJSONString(t, "GET", "/a b/x")))
	if res.RouteID != "nbsp" {
		t.Fatalf("routeId = %q, want nbsp", res.RouteID)
	}
	if want := "http://nbsp.internal/n/x"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}
