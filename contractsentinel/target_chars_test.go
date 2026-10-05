package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

// requestJSONString builds one request document from the already-decoded
// method and target strings, so JSON escapes such as "\n", "\t" and
// "\u0000" are emitted exactly the way a client sends them.
func requestJSONString(t *testing.T, method, target string) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		Method string `json:"method"`
		Target string `json:"target"`
	}{Method: method, Target: target})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return b
}

// TestTargetDirectControlCharactersRejected pins the direct-character rule:
// after JSON decoding, a space, a C0 control byte (U+0000..U+001F) or DEL
// (U+007F) appearing literally in the target — in the path, a parameter name
// or a parameter value — invalidates the whole request, regardless of which
// route would match and even when a transform would remove the carrying
// parameter. The reason names the first offending character as U+XXXX.
func TestTargetDirectControlCharactersRejected(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string // U+XXXX token for the first offending character
	}{
		{"newline after a matching prefix", "/api/orders\n", "U+000A"},
		{"carriage return in the path", "/api/orders\r", "U+000D"},
		{"tab in the path", "/api/orders\t/x", "U+0009"},
		{"null byte in the path", "/api/orders\x00/x", "U+0000"},
		{"end of transmission byte", "/api/x\x04", "U+0004"},
		{"delete byte in the path", "/api/x\x7f", "U+007F"},
		{"space in the path", "/api/orders next", "U+0020"},
		{"space in a parameter name", "/p?a b=1", "U+0020"},
		{"tab in a parameter name", "/p?a\tb=1", "U+0009"},
		{"null byte in a parameter name", "/p?a\x00b=1", "U+0000"},
		{"space in a parameter value", "/p?a=x y", "U+0020"},
		{"newline in a parameter value", "/p?a=1&b=x\ny", "U+000A"},
		{"tab in a valueless parameter", "/p?flag\t", "U+0009"},
		{"space before the question mark", "/p ?a=1", "U+0020"},
		{"space right after the question mark", "/p? a=1", "U+0020"},
		{"first offender is the earlier space, not the later newline", "/a b\nc", "U+0020"},
		{"first offender is a newline earlier than a later space", "/a\nb c", "U+000A"},
		{"first offender is the null byte at the front", "/\x00a b", "U+0000"},
	}
	cfg := mustConfig(t, sampleConfig)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The front door: ParseRequest rejects the decoded target.
			req, f := ParseRequest(requestJSONString(t, "GET", tc.target))
			if f == nil {
				t.Fatalf("ParseRequest(%q): expected invalid_request", tc.target)
			}
			if f.Code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", f.Code)
			}
			for _, want := range []string{"target", tc.want} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			if req != nil {
				t.Fatalf("a rejected request must not be returned, got %+v", req)
			}

			// A caller that bypasses ParseRequest gets the same failure from
			// Resolve, never a route selection or a partial resolution.
			res, rf := Resolve(cfg, &Request{Method: "GET", Target: tc.target})
			if rf == nil || rf.Code != "invalid_request" {
				t.Fatalf("Resolve(%q): got %+v, want invalid_request", tc.target, rf)
			}
			if !strings.Contains(rf.Reason, tc.want) {
				t.Fatalf("Resolve reason = %q, want substring %q", rf.Reason, tc.want)
			}
			if res != nil {
				t.Fatalf("Resolve(%q): got success %+v, want no resolution", tc.target, res)
			}
		})
	}
}

// TestTargetJSONEscapesDecodedThenRejected proves the rule operates on the
// decoded target: JSON string escapes such as "\n", "\t" and "\u0000" become
// the literal control byte once decoded and are rejected as such.
func TestTargetJSONEscapesDecodedThenRejected(t *testing.T) {
	cfg := mustConfig(t, sampleConfig)
	cases := []struct {
		name    string
		jsonDoc string
		want    string
	}{
		{"json newline escape", `{"method":"GET","target":"/api/orders\n"}`, "U+000A"},
		{"json tab escape", `{"method":"GET","target":"/api/orders\t"}`, "U+0009"},
		{"json carriage return escape", `{"method":"GET","target":"/api/orders\r"}`, "U+000D"},
		{"json null escape in a parameter value", `{"method":"GET","target":"/api?x=1\u0000"}`, "U+0000"},
		{"json uppercase unicode escape for del", `{"method":"GET","target":"/api/x\u007F"}`, "U+007F"},
		{"json unicode escape for space", `{"method":"GET","target":"/api/orders next"}`, "U+0020"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, f := ParseRequest([]byte(tc.jsonDoc))
			if f == nil || f.Code != "invalid_request" {
				t.Fatalf("ParseRequest: got req=%+v f=%+v, want invalid_request", req, f)
			}
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.want)
			}

			var doc struct {
				Method string `json:"method"`
				Target string `json:"target"`
			}
			if err := json.Unmarshal([]byte(tc.jsonDoc), &doc); err != nil {
				t.Fatal(err)
			}
			res, rf := Resolve(cfg, &Request{Method: doc.Method, Target: doc.Target})
			if rf == nil || rf.Code != "invalid_request" || res != nil {
				t.Fatalf("Resolve: got res=%+v rf=%+v, want invalid_request only", res, rf)
			}
			if !strings.Contains(rf.Reason, tc.want) {
				t.Fatalf("Resolve reason = %q, want substring %q", rf.Reason, tc.want)
			}
		})
	}
}

// TestTargetDirectCharacterCheckPrecedesRouting proves the check runs before
// route selection and query rewriting: a target with no matching route, a
// target that would create a conflict, and a target whose offending parameter
// a remove or set rule would delete or overwrite all still fail as
// invalid_request rather than route_not_found, route_conflict or a success
// that laundered the byte away.
func TestTargetDirectCharacterCheckPrecedesRouting(t *testing.T) {
	// No route matches the path; a direct newline must still be
	// invalid_request, never route_not_found.
	emptyCfg := mustConfig(t, `{"routes":[]}`)
	res, f := Resolve(emptyCfg, &Request{Method: "GET", Target: "/nothing\n"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("unmatched path: got res=%+v f=%+v, want invalid_request", res, f)
	}

	// Two GET routes tied on the same prefix would conflict for a clean
	// "/api" request; with a newline in the target the character error wins.
	conflictCfg := mustConfig(t, `{"routes":[
	  {"id":"a","methods":["GET"],"pathPrefix":"/api","upstream":"http://a.internal"},
	  {"id":"b","methods":["GET"],"pathPrefix":"/api","upstream":"http://b.internal"}
	]}`)
	if _, rf := Resolve(conflictCfg, mustReq(t, "GET", "/api")); rf == nil || rf.Code != "route_conflict" {
		t.Fatalf("sanity: clean target should conflict, got %+v", rf)
	}
	res, f = Resolve(conflictCfg, &Request{Method: "GET", Target: "/api\n"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("conflicting routes: got res=%+v f=%+v, want invalid_request before route_conflict", res, f)
	}

	// A remove rule would delete the parameter whose decoded name carries a
	// space; the request must fail before that rule can hide it.
	removeCfg := transformConfig(t, `[{"op":"remove","name":"bad name"}]`)
	res, f = Resolve(removeCfg, &Request{Method: "GET", Target: "/p?bad name=1&keep=2"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("remove hiding offender: got res=%+v f=%+v, want invalid_request", res, f)
	}

	// A remove rule matches a parameter name given verbatim with a newline
	// too (its decoded name contains the newline), and still cannot remove it
	// into validity.
	res, f = Resolve(removeCfg, &Request{Method: "GET", Target: "/p?bad name=1\n"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("remove + newline value: got res=%+v f=%+v, want invalid_request", res, f)
	}

	// A set rule would overwrite the value carrying the newline; the request
	// must fail before the merge.
	setCfg := transformConfig(t, `[{"op":"set","name":"a","value":"clean"}]`)
	res, f = Resolve(setCfg, &Request{Method: "GET", Target: "/p?a=1\n&b=2"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("set overwriting offender: got res=%+v f=%+v, want invalid_request", res, f)
	}

	// The same holds when the direct byte is in the name the set rule would
	// merge away.
	res, f = Resolve(setCfg, &Request{Method: "GET", Target: "/p?x\t=1&a=2"})
	if f == nil || f.Code != "invalid_request" || res != nil {
		t.Fatalf("set with offending name: got res=%+v f=%+v, want invalid_request", res, f)
	}
}

// TestTargetPercentEncodedControlCharactersUnaffected pins the distinction
// between direct and percent-encoded bytes: an encoded space, tab, newline,
// null or DEL is data, matching and joining keep the raw escape byte for
// byte (path escapes are never decoded before prefix matching), the query
// rules keep comparing decoded names and rewriting as before, and nothing is
// re-encoded, deleted or reordered. Non-ASCII content keeps its existing
// behavior too.
func TestTargetPercentEncodedControlCharactersUnaffected(t *testing.T) {
	cfg := mustConfig(t, sampleConfig)
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "encoded space extends the segment, so /api/orders prefix does not match",
			target:   "/api/orders%20next",
			routeID:  "api",
			upstream: "http://api.internal/v1/orders%20next",
		},
		{
			name:     "encoded newline and tab in a query value stay verbatim",
			target:   "/api/orders?note=%0A%09",
			routeID:  "orders",
			upstream: "http://orders.internal/?note=%0A%09",
		},
		{
			name:     "encoded space in a path segment matches the raw prefix",
			target:   "/users/a%20b",
			routeID:  "users",
			upstream: "http://users.internal/u/a%20b",
		},
		{
			name:     "encoded null and del in a query value stay verbatim",
			target:   "/api?x=%00%7F",
			routeID:  "api",
			upstream: "http://api.internal/v1/?x=%00%7F",
		},
		{
			name:     "encoded control byte in a parameter name is still a parameter",
			target:   "/api?a%09b=1",
			routeID:  "api",
			upstream: "http://api.internal/v1/?a%09b=1",
		},
		{
			name:     "non ascii path and query keep their existing behavior",
			target:   "/api/orders?note=中文&p=/订单",
			routeID:  "orders",
			upstream: "http://orders.internal/?note=中文&p=/订单",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, f := ParseRequest(requestJSONString(t, "GET", tc.target))
			if f != nil {
				t.Fatalf("ParseRequest(%q): unexpected failure %+v", tc.target, f)
			}
			res, rf := Resolve(cfg, req)
			if rf != nil {
				t.Fatalf("Resolve(%q): unexpected failure %+v", tc.target, rf)
			}
			if res.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", res.RouteID, tc.routeID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}

	// Transforms still compare decoded names and rewrite only the hit
	// parameter; a parameter carrying encoded control bytes is never touched.
	got := transformResult(t, `[{"op":"remove","name":"a"}]`, "/p?note=%0A%09&a=1")
	if want := "http://h.internal/base/p?note=%0A%09"; got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
	got = transformResult(t, `[{"op":"set","name":"a","value":""}]`, "/p?x=%00%7F&a=1")
	if want := "http://h.internal/base/p?x=%00%7F&a="; got != want {
		t.Fatalf("upstreamURL = %q, want %q", got, want)
	}
}

// TestTargetCharacterRulePrecedence pins the order of the request checks:
// config errors keep winning before the request is examined at all (CLI),
// and within one request syntax, shape, field types, method content and the
// existing target checks (absolute target, fragment, malformed percent
// escape) all precede the new direct-character rule.
func TestTargetCharacterRulePrecedence(t *testing.T) {
	// A malformed percent escape is reported before the direct newline later
	// in the same target.
	for _, src := range []string{
		`{"method":"GET","target":"/a%zz\n"}`,
		`{"method":"GET","target":"/a%2\n"}`,
	} {
		_, f := ParseRequest([]byte(src))
		if f == nil || f.Code != "invalid_request" {
			t.Fatalf("%s: got %+v, want invalid_request", src, f)
		}
		if !strings.Contains(f.Reason, "percent escape") {
			t.Fatalf("%s: reason = %q, want the percent-escape reason first", src, f.Reason)
		}
		if strings.Contains(f.Reason, "U+") {
			t.Fatalf("%s: percent-escape check must precede the character check: %q", src, f.Reason)
		}
	}

	// Fragment check precedes the direct character after the '#'.
	_, f := ParseRequest([]byte(`{"method":"GET","target":"/a#f\n"}`))
	if f == nil || !strings.Contains(f.Reason, "fragment") {
		t.Fatalf("got %+v, want the fragment reason first", f)
	}

	// A non-absolute target precedes the character rule.
	_, f = ParseRequest([]byte(`{"method":"GET","target":"a b\n"}`))
	if f == nil || !strings.Contains(f.Reason, "start with /") {
		t.Fatalf("got %+v, want the start-with-/ reason first", f)
	}

	// Method content precedes the target character rule.
	_, f = ParseRequest([]byte(`{"method":"GE T","target":"/a\n"}`))
	if f == nil || !strings.Contains(f.Reason, "legal HTTP method") {
		t.Fatalf("got %+v, want the method reason first", f)
	}

	// A bad config still beats a target with a direct newline: ParseConfig
	// fails and hands back no config at all.
	badCfg := `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"ftp://h"}]}`
	cfg, cf := ParseConfig([]byte(badCfg))
	if cf == nil || cf.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, cf)
	}
	if cfg != nil {
		t.Fatal("a rejected config must not be returned")
	}
}
