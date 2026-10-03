package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustConfig(t *testing.T, src string) *Config {
	t.Helper()
	cfg, f := ParseConfig([]byte(src))
	if f != nil {
		t.Fatalf("unexpected config failure: %+v", f)
	}
	return cfg
}

func resolveJSON(t *testing.T, cfg *Config, reqSrc string) *Resolution {
	t.Helper()
	req, f := ParseRequest([]byte(reqSrc))
	if f != nil {
		t.Fatalf("unexpected request failure: %+v", f)
	}
	res, rf := Resolve(cfg, req)
	if rf != nil {
		t.Fatalf("unexpected resolve failure: %+v", rf)
	}
	return res
}

const sampleConfig = `{
  "routes": [
    {"id": "api",    "methods": ["GET"],        "pathPrefix": "/api",         "upstream": "http://api.internal/v1"},
    {"id": "api-v2", "methods": ["*"],          "pathPrefix": "/api/v2",      "upstream": "https://api.internal:8443/v2"},
    {"id": "orders", "methods": ["GET", "POST"],"pathPrefix": "/api/orders", "upstream": "http://orders.internal"},
    {"id": "root",   "methods": ["*"],          "pathPrefix": "/",            "upstream": "https://fallback.internal/base/"},
    {"id": "users",  "methods": ["GET"],        "pathPrefix": "/users",       "upstream": "http://users.internal/u"}
  ]
}`

func TestResolveBasicMatchAndJoin(t *testing.T) {
	cfg := mustConfig(t, sampleConfig)

	cases := []struct {
		name     string
		request  string
		routeID  string
		upstream string
	}{
		{
			name:     "exact prefix strips and joins base path",
			request:  `{"method":"GET","target":"/api"}`,
			routeID:  "api",
			upstream: "http://api.internal/v1/",
		},
		{
			name:     "prefix with deeper path joins on one slash",
			request:  `{"method":"GET","target":"/api/orders/42"}`,
			routeID:  "orders",
			upstream: "http://orders.internal/42",
		},
		{
			name:     "post also matches concrete method list",
			request:  `{"method":"POST","target":"/api/orders"}`,
			routeID:  "orders",
			upstream: "http://orders.internal/",
		},
		{
			name:     "longest prefix beats shorter on shared path",
			request:  `{"method":"GET","target":"/api/orders"}`,
			routeID:  "orders",
			upstream: "http://orders.internal/",
		},
		{
			name:     "upstream trailing base slash collapses to one",
			request:  `{"method":"GET","target":"/users/7/profile"}`,
			routeID:  "users",
			upstream: "http://users.internal/u/7/profile",
		},
		{
			name:     "root fallback keeps the full path",
			request:  `{"method":"GET","target":"/healthz"}`,
			routeID:  "root",
			upstream: "https://fallback.internal/base/healthz",
		},
		{
			name:     "root prefix with root target keeps junction slash",
			request:  `{"method":"GET","target":"/"}`,
			routeID:  "root",
			upstream: "https://fallback.internal/base/",
		},
		{
			name:     "wildcard method accepts unusual but legal method",
			request:  `{"method":"PROPFIND","target":"/api/v2/things/9"}`,
			routeID:  "api-v2",
			upstream: "https://api.internal:8443/v2/things/9",
		},
		{
			name:     "query string is ignored for matching but preserved verbatim",
			request:  `{"method":"GET","target":"/api/orders/1?expand=items&a=&a=2&b=%41%2f"}`,
			routeID:  "orders",
			upstream: "http://orders.internal/1?expand=items&a=&a=2&b=%41%2f",
		},
		{
			name:     "empty query string stays empty",
			request:  `{"method":"GET","target":"/api?"}`,
			routeID:  "api",
			upstream: "http://api.internal/v1/?",
		},
		{
			name:     "encoded path is matched raw and kept raw",
			request:  `{"method":"GET","target":"/users/a%20b%2Fc"}`,
			routeID:  "users",
			upstream: "http://users.internal/u/a%20b%2Fc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, tc.request)
			if res.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", res.RouteID, tc.routeID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}
}

func TestResolveJunctionSlashCollapse(t *testing.T) {
	// Only the run where the base path's trailing slashes meet the
	// remainder's leading slashes is collapsed to a single slash; slashes,
	// dot segments and percent escapes anywhere else stay byte for byte.
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "multi", "methods": ["GET"], "pathPrefix": "/api",  "upstream": "http://backend.internal/base///"},
	    {"id": "plain", "methods": ["GET"], "pathPrefix": "/v",    "upstream": "http://plain.internal/base"},
	    {"id": "nobase","methods": ["GET"], "pathPrefix": "/n",    "upstream": "http://nb.internal:8080"},
	    {"id": "root",  "methods": ["*"],   "pathPrefix": "/",     "upstream": "https://fallback.internal/base//"}
	  ]
	}`)

	cases := []struct {
		name     string
		request  string
		routeID  string
		upstream string
	}{
		{
			name:     "multi-slash base and remainder collapse at the junction",
			request:  `{"method":"GET","target":"/api//orders/7?a=1&a=&x=%2f+"}`,
			routeID:  "multi",
			upstream: "http://backend.internal/base/orders/7?a=1&a=&x=%2f+",
		},
		{
			name:     "exact prefix with multi-slash base keeps one trailing slash",
			request:  `{"method":"GET","target":"/api"}`,
			routeID:  "multi",
			upstream: "http://backend.internal/base/",
		},
		{
			name:     "remainder made only of slashes ends in the one junction slash",
			request:  `{"method":"GET","target":"/api///"}`,
			routeID:  "multi",
			upstream: "http://backend.internal/base/",
		},
		{
			name:     "internal slashes and dot segments are left untouched",
			request:  `{"method":"GET","target":"/api//a//b/../c/"}`,
			routeID:  "multi",
			upstream: "http://backend.internal/base/a//b/../c/",
		},
		{
			name:     "encoded slash right at the junction is data, not a junction slash",
			request:  `{"method":"GET","target":"/api/%2f/x"}`,
			routeID:  "multi",
			upstream: "http://backend.internal/base/%2f/x",
		},
		{
			name:     "plain base with doubled leading remainder slashes collapses too",
			request:  `{"method":"GET","target":"/v//orders"}`,
			routeID:  "plain",
			upstream: "http://plain.internal/base/orders",
		},
		{
			name:     "upstream without a base path still joins with one slash",
			request:  `{"method":"GET","target":"/n//orders"}`,
			routeID:  "nobase",
			upstream: "http://nb.internal:8080/orders",
		},
		{
			name:     "upstream without a base path and exact prefix keeps the slash",
			request:  `{"method":"GET","target":"/n"}`,
			routeID:  "nobase",
			upstream: "http://nb.internal:8080/",
		},
		{
			name:     "root request keeps one junction slash over a multi-slash base",
			request:  `{"method":"GET","target":"/"}`,
			routeID:  "root",
			upstream: "https://fallback.internal/base/",
		},
		{
			name:     "root request leading multiple slashes follows the junction rule",
			request:  `{"method":"GET","target":"///healthz//"}`,
			routeID:  "root",
			upstream: "https://fallback.internal/base/healthz//",
		},
		{
			name:     "root internal slashes and dot segments are preserved",
			request:  `{"method":"GET","target":"/a//b/./c?z=1&&w="}`,
			routeID:  "root",
			upstream: "https://fallback.internal/base/a//b/./c?z=1&&w=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, tc.request)
			if res.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", res.RouteID, tc.routeID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}
}

func TestResolveSegmentBoundary(t *testing.T) {
	cfg := mustConfig(t, sampleConfig)

	// /api must not match /apiv2; it falls through to the root route.
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/apiv2/x"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root", res.RouteID)
	}
	if want := "https://fallback.internal/base/apiv2/x"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// "%2F" is an encoded slash in the remainder, never a segment separator.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/api%2Fv2/secret"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root (encoded slash is not a boundary)", res.RouteID)
	}
}

func TestResolveConcreteMethodBeatsWildcard(t *testing.T) {
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "wide",   "methods": ["*"],  "pathPrefix": "/things", "upstream": "http://wide.internal"},
	    {"id": "exact",  "methods": ["GET"],"pathPrefix": "/things", "upstream": "http://exact.internal"}
	  ]
	}`)

	res := resolveJSON(t, cfg, `{"method":"GET","target":"/things/1"}`)
	if res.RouteID != "exact" {
		t.Fatalf("routeId = %q, want exact (concrete method wins)", res.RouteID)
	}

	// A non-GET request can only use the wildcard route.
	res = resolveJSON(t, cfg, `{"method":"POST","target":"/things/1"}`)
	if res.RouteID != "wide" {
		t.Fatalf("routeId = %q, want wide", res.RouteID)
	}

	// Method names are case-sensitive: a concrete "GET" route must not match "get".
	getOnly := mustConfig(t, `{"routes":[
	  {"id":"only-get","methods":["GET"],"pathPrefix":"/things","upstream":"http://g.internal"}]}`)
	if _, rf := Resolve(getOnly, mustReq(t, "get", "/things/1")); rf == nil || rf.Code != "route_not_found" {
		t.Fatalf("got %+v, want route_not_found for lowercase method", rf)
	}
	// ...but a wildcard route does accept any legal method token, incl. "get".
	res = resolveJSON(t, cfg, `{"method":"get","target":"/things/1"}`)
	if res.RouteID != "wide" {
		t.Fatalf("routeId = %q, want wide (wildcard matches any legal method)", res.RouteID)
	}
}

func TestResolveConflict(t *testing.T) {
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "zeta",  "methods": ["GET"], "pathPrefix": "/things", "upstream": "http://z.internal"},
	    {"id": "alpha", "methods": ["GET"], "pathPrefix": "/things", "upstream": "http://a.internal"},
	    {"id": "mid",   "methods": ["GET"], "pathPrefix": "/things", "upstream": "http://m.internal"}
	  ]
	}`)
	req, f := ParseRequest([]byte(`{"method":"GET","target":"/things"}`))
	if f != nil {
		t.Fatalf("unexpected request failure: %+v", f)
	}
	_, rf := Resolve(cfg, req)
	if rf == nil {
		t.Fatal("expected route_conflict")
	}
	if rf.Code != "route_conflict" {
		t.Fatalf("code = %q, want route_conflict", rf.Code)
	}
	want := []string{"alpha", "mid", "zeta"}
	if len(rf.Candidates) != len(want) {
		t.Fatalf("candidates = %v, want %v", rf.Candidates, want)
	}
	for i := range want {
		if rf.Candidates[i] != want[i] {
			t.Fatalf("candidates = %v, want sorted %v", rf.Candidates, want)
		}
	}

	// Concrete vs wildcard at same prefix is NOT a conflict.
	cfg2 := mustConfig(t, `{
	  "routes": [
	    {"id": "b-wild", "methods": ["*"],  "pathPrefix": "/things", "upstream": "http://w.internal"},
	    {"id": "a-get",  "methods": ["GET"],"pathPrefix": "/things", "upstream": "http://g.internal"}
	  ]
	}`)
	res := resolveJSON(t, cfg2, `{"method":"GET","target":"/things/x"}`)
	if res.RouteID != "a-get" {
		t.Fatalf("routeId = %q, want a-get", res.RouteID)
	}

	// Two wildcards with no concrete entry remain a conflict.
	cfg3 := mustConfig(t, `{
	  "routes": [
	    {"id": "w1", "methods": ["*"], "pathPrefix": "/things", "upstream": "http://w1.internal"},
	    {"id": "w2", "methods": ["*"], "pathPrefix": "/things", "upstream": "http://w2.internal"}
	  ]
	}`)
	_, rf = Resolve(cfg3, mustReq(t, "POST", "/things/x"))
	if rf == nil || rf.Code != "route_conflict" {
		t.Fatalf("got %+v, want route_conflict between wildcard routes", rf)
	}
}

// reversedConfig returns the same configuration with its routes array in
// reverse order. Selection must not depend on configuration order, so every
// scenario in this file that pins a winner or a conflict is also run against
// the reversed routes.
func reversedConfig(t *testing.T, src string) string {
	t.Helper()
	var doc struct {
		Routes []json.RawMessage `json:"routes"`
	}
	if err := json.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	for i, j := 0, len(doc.Routes)-1; i < j; i, j = i+1, j-1 {
		doc.Routes[i], doc.Routes[j] = doc.Routes[j], doc.Routes[i]
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return string(out)
}

// resolveBothOrders resolves one request against src and against the same
// routes in reverse order, requiring both to succeed identically.
func resolveBothOrders(t *testing.T, src, request string) *Resolution {
	t.Helper()
	res := resolveJSON(t, mustConfig(t, src), request)
	rev := resolveJSON(t, mustConfig(t, reversedConfig(t, src)), request)
	if *rev != *res {
		t.Fatalf("reversed route order changed the result: %+v vs %+v", res, rev)
	}
	return res
}

func TestResolveLongestWildcardBeatsShorterConcrete(t *testing.T) {
	// Selection runs longest-prefix first and only then compares concrete
	// against wildcard methods. The two GET routes on the shorter /api
	// prefix would conflict with each other if they ever reached the method
	// comparison, but the longer wildcard prefix must discard them before
	// that — no conflict, and the result belongs entirely to the longer
	// route: its id, its prefix stripped, its upstream base path.
	const src = `{
	  "routes": [
	    {"id": "short-get-1", "methods": ["GET"], "pathPrefix": "/api",    "upstream": "http://one.internal/v1"},
	    {"id": "short-get-2", "methods": ["GET"], "pathPrefix": "/api",    "upstream": "http://two.internal/v1"},
	    {"id": "long-wild",   "methods": ["*"],   "pathPrefix": "/api/v2", "upstream": "http://v2.internal/base"}
	  ]
	}`

	res := resolveBothOrders(t, src, `{"method":"GET","target":"/api/v2/items/9?keep=1&x=%2f+a&flag"}`)
	if res.RouteID != "long-wild" {
		t.Errorf("routeId = %q, want long-wild (longest prefix wins over shorter concrete routes)", res.RouteID)
	}
	// /api/v2 is stripped, the remainder joins onto long-wild's own base
	// path, and with no queryTransforms the raw query survives verbatim.
	if want := "http://v2.internal/base/items/9?keep=1&x=%2f+a&flag"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// A path exactly equal to the longer prefix follows the same order, and
	// the join keeps exactly one slash at the junction.
	res = resolveBothOrders(t, src, `{"method":"GET","target":"/api/v2"}`)
	if res.RouteID != "long-wild" {
		t.Errorf("routeId = %q, want long-wild", res.RouteID)
	}
	if want := "http://v2.internal/base/"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q (one junction slash)", res.UpstreamURL, want)
	}
}

func TestResolveConcreteBeatsWildcardAtLongestPrefix(t *testing.T) {
	// At the longest matching prefix a concrete GET route beats a wildcard
	// route; methods without a concrete entry still fall to the wildcard.
	// The root wildcard never competes: it loses on prefix length first.
	const src = `{
	  "routes": [
	    {"id": "root-wild", "methods": ["*"],   "pathPrefix": "/",       "upstream": "http://root.internal/r"},
	    {"id": "t-wild",    "methods": ["*"],   "pathPrefix": "/things", "upstream": "http://wild.internal/w"},
	    {"id": "t-get",     "methods": ["GET"], "pathPrefix": "/things", "upstream": "http://get.internal/g"}
	  ]
	}`

	res := resolveBothOrders(t, src, `{"method":"GET","target":"/things/1"}`)
	if res.RouteID != "t-get" {
		t.Errorf("routeId = %q, want t-get (concrete beats wildcard at the longest prefix)", res.RouteID)
	}
	if want := "http://get.internal/g/1"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	res = resolveBothOrders(t, src, `{"method":"PATCH","target":"/things/1"}`)
	if res.RouteID != "t-wild" {
		t.Errorf("routeId = %q, want t-wild (no concrete PATCH entry)", res.RouteID)
	}
	if want := "http://wild.internal/w/1"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestResolveRouteListingConcreteAndWildcardCountsOnce(t *testing.T) {
	// A route whose methods list holds both GET and "*" is a concrete match
	// for a GET request, and it is still a single candidate: matching two
	// method entries must not turn the route into a conflict with itself.
	const src = `{
	  "routes": [
	    {"id": "both", "methods": ["GET", "*"], "pathPrefix": "/both", "upstream": "http://both.internal/b"}
	  ]
	}`
	res := resolveBothOrders(t, src, `{"method":"GET","target":"/both/x"}`)
	if res.RouteID != "both" {
		t.Errorf("routeId = %q, want both (no self-conflict from GET plus *)", res.RouteID)
	}
	if want := "http://both.internal/b/x"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// Its GET entry is concrete, so it also wins over a plain wildcard route
	// at the same prefix.
	const two = `{
	  "routes": [
	    {"id": "wild", "methods": ["*"],        "pathPrefix": "/both", "upstream": "http://wild.internal/w"},
	    {"id": "both", "methods": ["GET", "*"], "pathPrefix": "/both", "upstream": "http://both.internal/b"}
	  ]
	}`
	res = resolveBothOrders(t, two, `{"method":"GET","target":"/both/x"}`)
	if res.RouteID != "both" {
		t.Errorf("routeId = %q, want both (concrete GET entry beats the wildcard route)", res.RouteID)
	}
	if want := "http://both.internal/b/x"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestResolveConflictOnlyAmongLongestPrefixConcrete(t *testing.T) {
	// The conflict set is whatever survives both selection steps: the
	// shorter-prefix GET route is discarded by prefix length and the
	// same-prefix wildcard by the concrete comparison, so only the two
	// concrete GET routes at the longest prefix remain, and no route is
	// returned as a success.
	const src = `{
	  "routes": [
	    {"id": "short", "methods": ["GET"], "pathPrefix": "/a",   "upstream": "http://short.internal"},
	    {"id": "wild",  "methods": ["*"],   "pathPrefix": "/a/b", "upstream": "http://wild.internal"},
	    {"id": "zeta",  "methods": ["GET"], "pathPrefix": "/a/b", "upstream": "http://z.internal"},
	    {"id": "alpha", "methods": ["GET"], "pathPrefix": "/a/b", "upstream": "http://a.internal"}
	  ]
	}`
	for _, cfgSrc := range []string{src, reversedConfig(t, src)} {
		cfg := mustConfig(t, cfgSrc)
		res, rf := Resolve(cfg, mustReq(t, "GET", "/a/b/x"))
		if rf == nil {
			t.Fatalf("got success %+v, want route_conflict", res)
		}
		if rf.Code != "route_conflict" {
			t.Fatalf("code = %q, want route_conflict", rf.Code)
		}
		want := []string{"alpha", "zeta"}
		if len(rf.Candidates) != len(want) {
			t.Fatalf("candidates = %v, want exactly %v (shorter prefix and wildcard excluded)", rf.Candidates, want)
		}
		for i := range want {
			if rf.Candidates[i] != want[i] {
				t.Fatalf("candidates = %v, want lexicographic %v", rf.Candidates, want)
			}
		}
	}
}

func mustReq(t *testing.T, method, target string) *Request {
	t.Helper()
	req, f := ParseRequest([]byte(`{"method":"` + method + `","target":"` + target + `"}`))
	if f != nil {
		t.Fatalf("unexpected request failure: %+v", f)
	}
	return req
}

func TestResolveNotFound(t *testing.T) {
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "api", "methods": ["POST"], "pathPrefix": "/api", "upstream": "http://api.internal"}
	  ]
	}`)
	req, _ := ParseRequest([]byte(`{"method":"GET","target":"/api/x"}`))
	if _, f := Resolve(cfg, req); f == nil || f.Code != "route_not_found" {
		t.Fatalf("got %+v, want route_not_found", f)
	}

	emptyCfg := mustConfig(t, `{"routes": []}`)
	if _, f := Resolve(emptyCfg, req); f == nil || f.Code != "route_not_found" {
		t.Fatalf("got %+v, want route_not_found on empty config", f)
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		want    string // reason substring
		located bool   // whether the reason should locate the route
	}{
		{"not json", `{not json`, "not valid JSON", false},
		{"empty id", `{"routes":[{"id":"","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"}]}`, "id must be non-empty", true},
		{"duplicate id", `{"routes":[
		  {"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h1"},
		  {"id":"x","methods":["GET"],"pathPrefix":"/b","upstream":"http://h2"}]}`, "duplicate id", true},
		{"empty methods", `{"routes":[{"id":"x","methods":[],"pathPrefix":"/a","upstream":"http://h"}]}`, "non-empty", true},
		{"bad method token", `{"routes":[{"id":"x","methods":["GE T"],"pathPrefix":"/a","upstream":"http://h"}]}`, "invalid method", true},
		{"prefix not absolute", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"a","upstream":"http://h"}]}`, "start with /", true},
		{"prefix trailing slash", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a/","upstream":"http://h"}]}`, "end with /", true},
		{"root trailing slash allowed", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/","upstream":"http://h"}]}`, "", true},
		{"prefix with query", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a?x=1","upstream":"http://h"}]}`, "query string or fragment", true},
		{"prefix with fragment", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a#f","upstream":"http://h"}]}`, "query string or fragment", true},
		{"prefix bad percent escape", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a%2","upstream":"http://h"}]}`, "percent escape", true},
		{"upstream relative", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"/path"}]}`, "absolute http or https", true},
		{"upstream wrong scheme", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"ftp://h"}]}`, "absolute http or https", true},
		{"upstream missing host", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http:///path"}]}`, "include a host", true},
		{"upstream with query", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h?x=1"}]}`, "query string or fragment", true},
		{"upstream with fragment", `{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h#f"}]}`, "query string or fragment", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, f := ParseConfig([]byte(tc.src))
			if tc.want == "" {
				if f != nil {
					t.Fatalf("unexpected failure: %+v", f)
				}
				return
			}
			if f == nil {
				t.Fatalf("expected invalid_config containing %q", tc.want)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.want)
			}
			if tc.located && !strings.Contains(f.Reason, "route ") {
				t.Fatalf("reason = %q should locate the route", f.Reason)
			}
		})
	}
}

func TestInvalidConfigFieldTypes(t *testing.T) {
	// Unlike TestInvalidConfig's missing/illegal-value cases, these exercise
	// fields whose JSON type itself is wrong: valid JSON that cannot satisfy
	// the field's type must still be invalid_config, but the reason has to
	// name the route position (and a valid string id), distinguish it from a
	// JSON syntax failure, and say why the field could not be read.
	goodRoute := `"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"`

	cases := []struct {
		name      string
		src       string
		want      []string // all must appear in the reason
		forbidden []string // none may appear in the reason
	}{
		{
			name: "methods string on second route, id after the bad field",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a"},
			  {"methods":"GET","id":"orders","pathPrefix":"/api/orders","upstream":"http://o"}
			]}`,
			want: []string{"route 2", `"orders"`, "methods must be an array"},
		},
		{
			name: "methods null",
			src:  `{"routes":[{` + goodRoute + `,"methods":null}]}`,
			want: []string{"route 1", `"x"`, "methods must be an array"},
		},
		{
			name: "methods is an object",
			src:  `{"routes":[{` + goodRoute + `,"methods":{"GET":true}}]}`,
			want: []string{"route 1", `"x"`, "methods must be an array"},
		},
		{
			name: "numeric entry inside a legal methods array",
			src: `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://a"},
			  {"id":"orders","methods":["GET",1],"pathPrefix":"/api/orders","upstream":"http://o"}
			]}`,
			want: []string{"route 2", `"orders"`, "methods entry 2 must be a string"},
		},
		{
			name: "null entry inside methods",
			src:  `{"routes":[{` + goodRoute + `,"methods":[null]}]}`,
			want: []string{"route 1", "methods entry 1 must be a string"},
		},
		{
			name:      "id is a number",
			src:       `{"routes":[{"id":1,"methods":["GET"],"pathPrefix":"/a","upstream":"http://h"}]}`,
			want:      []string{"route 1", "id must be a string"},
			forbidden: []string{"(id "},
		},
		{
			name:      "id is an object",
			src:       `{"routes":[{"id":{"v":1},"methods":["GET"],"pathPrefix":"/a","upstream":"http://h"}]}`,
			want:      []string{"route 1", "id must be a string"},
			forbidden: []string{"(id "},
		},
		{
			name: "pathPrefix is a number, id written after it",
			src:  `{"routes":[{"methods":["GET"],"pathPrefix":1,"id":"orders","upstream":"http://o"}]}`,
			want: []string{"route 1", `"orders"`, "pathPrefix must be a string"},
		},
		{
			name: "upstream is a boolean, id written after it",
			src:  `{"routes":[{"methods":["GET"],"pathPrefix":"/a","upstream":true,"id":"orders"}]}`,
			want: []string{"route 1", `"orders"`, "upstream must be a string"},
		},
		{
			name: "routes entry is not an object",
			src:  `{"routes":[42]}`,
			want: []string{"route 1", "route entry must be a JSON object"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, f := ParseConfig([]byte(tc.src))
			if f == nil {
				t.Fatalf("expected invalid_config")
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			if strings.Contains(f.Reason, "not valid JSON") {
				t.Fatalf("field type error must not be described as a JSON syntax failure: %q", f.Reason)
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, bad := range tc.forbidden {
				if strings.Contains(f.Reason, bad) {
					t.Fatalf("reason = %q must not contain %q", f.Reason, bad)
				}
			}
		})
	}

	// Broken JSON syntax stays a parse failure and never gets a guessed
	// route position, even when the corruption is inside the routes array.
	for _, src := range []string{`{not json`, `{"routes": [{"id":"x"} broken`} {
		_, f := ParseConfig([]byte(src))
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("got %+v, want invalid_config for %q", f, src)
		}
		if !strings.Contains(f.Reason, "not valid JSON") {
			t.Fatalf("reason = %q, want a JSON parse failure", f.Reason)
		}
		if strings.Contains(f.Reason, "route 1") {
			t.Fatalf("syntax failure must not guess a route position: %q", f.Reason)
		}
	}

	// Fixing the second route's methods lets the request resolve normally,
	// including through the first route it originally matched.
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"orders","methods":["GET"],"pathPrefix":"/api/orders","upstream":"http://orders.internal"}
	]}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/api/items"}`)
	if res.RouteID != "api" || res.UpstreamURL != "http://api.internal/v1/items" {
		t.Fatalf("got %+v, want api / http://api.internal/v1/items", res)
	}
}

func TestInvalidRequest(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"not json", `{bad`, "not valid JSON"},
		{"missing method", `{"target":"/a"}`, "method is required"},
		{"illegal method", `{"method":"GE T","target":"/a"}`, "legal HTTP method"},
		{"target not absolute", `{"method":"GET","target":"a"}`, "start with /"},
		{"empty target", `{"method":"GET","target":""}`, "start with /"},
		{"fragment", `{"method":"GET","target":"/a#f"}`, "fragment"},
		{"bad percent escape", `{"method":"GET","target":"/a%zz"}`, "percent escape"},
		{"truncated percent escape", `{"method":"GET","target":"/a%2"}`, "percent escape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, f := ParseRequest([]byte(tc.src))
			if f == nil {
				t.Fatalf("expected invalid_request containing %q", tc.want)
			}
			if f.Code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", f.Code)
			}
			if !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("reason = %q, want substring %q", f.Reason, tc.want)
			}
		})
	}
}

func TestEncodedPrefixBoundary(t *testing.T) {
	// A prefix that itself contains an encoded slash is matched against the
	// raw target; the encoded slash is data in the same segment.
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "encoded", "methods": ["*"], "pathPrefix": "/files/a%2Fb", "upstream": "http://files.internal/f"}
	  ]
	}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/files/a%2Fb/x"}`)
	if res.RouteID != "encoded" || res.UpstreamURL != "http://files.internal/f/x" {
		t.Fatalf("got %+v", res)
	}
	if _, f := Resolve(cfg, mustReq(t, "GET", "/files/a/b/x")); f == nil || f.Code != "route_not_found" {
		t.Fatalf("got %+v, want not found: literal slash must not match %%2F prefix", f)
	}
}

func TestResolutionJSONShape(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[{"id":"r1","methods":["GET"],"pathPrefix":"/","upstream":"http://h"}]}`)
	res := resolveJSON(t, cfg, `{"method":"GET","target":"/p?q=1"}`)
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"routeId":"r1","upstreamURL":"http://h/p?q=1"}` {
		t.Fatalf("json = %s", out)
	}
}

func TestFailureJSONShape(t *testing.T) {
	f := failuref("route_conflict", "boom")
	f.Candidates = []string{"b", "a"}
	out, _ := json.Marshal(f)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["code"] != "route_conflict" || got["reason"] != "boom" {
		t.Fatalf("unexpected json: %s", out)
	}
}
