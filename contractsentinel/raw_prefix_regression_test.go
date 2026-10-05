// Regression coverage for prefix matching on the raw, still-encoded path.
//
// A configured prefix and a request path that are identical once
// percent-decoded are still different spellings: selection compares the
// original bytes, so "/files/a%2Fb", "/files/a%2fb" and "/files/a/b" are
// three prefixes that coexist in one config, and a request only ever
// considers the routes whose raw prefix it actually hits. The same rule
// separates an ordinary character from its percent encoding ("/item/A"
// vs "/item/%41"), keeps "%2F"/"%2f" from acting as a segment separator,
// and keeps the query string — even one whose text contains another
// route's full prefix — out of the candidate set.
//
// These tests pin the existing behavior end to end through ParseConfig,
// ParseRequest and Resolve; none of the public entry points, success
// output or failure codes is changed.
package contractsentinel

import "testing"

// rawPrefixConfig carries every distinct spelling at once: the three
// "/files/a<b>" prefixes (encoded slash upper case, encoded slash lower
// case and a literal slash), the "/item/A" vs "/item/%41" pair, and the
// wildcard root that serves everything the specific prefixes miss.
const rawPrefixConfig = `{
  "routes": [
    {"id": "files-enc-upper", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://upper.internal/up"},
    {"id": "files-enc-lower", "methods": ["GET"], "pathPrefix": "/files/a%2fb", "upstream": "http://lower.internal/lo"},
    {"id": "files-literal",   "methods": ["GET"], "pathPrefix": "/files/a/b",   "upstream": "http://literal.internal/li"},
    {"id": "item-plain",      "methods": ["GET"], "pathPrefix": "/item/A",     "upstream": "http://plain.internal/p"},
    {"id": "item-encoded",    "methods": ["GET"], "pathPrefix": "/item/%41",   "upstream": "http://encoded.internal/e"},
    {"id": "root",            "methods": ["*"],   "pathPrefix": "/",           "upstream": "https://fallback.internal/base/"}
  ]
}`

// TestPrefixMatchRawEncodingBoundary pins the raw-string decision itself:
// percent-encoding is never decoded, percent-hex case is significant, the
// boundary must be a literal slash, and the root prefix matches everything.
func TestPrefixMatchRawEncodingBoundary(t *testing.T) {
	cases := []struct {
		prefix string
		path   string
		want   bool
	}{
		{"/files/a%2Fb", "/files/a%2Fb", true},           // exact
		{"/files/a%2Fb", "/files/a%2Fb/x", true},         // boundary slash
		{"/files/a%2Fb", "/files/a%2fb", false},          // decoded-equal but raw spelling differs (%2F vs %2f)
		{"/files/a%2Fb", "/files/a%2fb/x", false},        // hex case differs, even with a boundary slash
		{"/files/a%2Fb", "/files/a/b", false},            // literal slash never matches an encoded one
		{"/files/a%2Fb", "/files/a%2Fb%2Fsecret", false}, // "%2F" extends the same segment
		{"/files/a%2Fb", "/files/a%2Fb%2fsecret", false}, // "%2f" is not a separator either
		{"/files/a%2Fb", "/files/a%2Fbx", false},         // an ordinary character is not a boundary
		{"/files/a%2fb", "/files/a%2fbox", false},        // same for the lower-case spelling
		{"/files/a/b", "/files/a/bx", false},             // literal prefix followed by an ordinary character
		{"/item/A", "/item/AB", false},                   // plain character continuation
		{"/item/%41", "/item/%41B", false},               // encoded prefix followed by an ordinary character
		{"/item/%41", "/item/%41%2frest", false},         // encoded slash after the prefix is data
		{"/item/%41", "/item/%41", true},
		{"/item/%41", "/item/%41/x", true},
		{"/item/A", "/item/%41", false},        // "A" and "%41" are distinct raw prefixes
		{"/", "/files/a%2Fb%2fanything", true}, // root matches every origin path
	}
	for _, tc := range cases {
		t.Run(tc.prefix+"|"+tc.path, func(t *testing.T) {
			if got := prefixMatch(tc.prefix, tc.path); got != tc.want {
				t.Errorf("prefixMatch(%q, %q) = %v, want %v", tc.prefix, tc.path, got, tc.want)
			}
		})
	}
}

// TestResolveRawPrefixSpellingIsDistinct drives selection with all three
// files spellings (and the item plain/encoded pair) configured together.
// Whichever raw spelling the request uses, only the route with that exact
// prefix may be selected — never one whose prefix merely decodes to the
// same path or only differs in percent-hex case.
func TestResolveRawPrefixSpellingIsDistinct(t *testing.T) {
	cfg := mustConfig(t, rawPrefixConfig)

	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "upper case encoded slash, exact prefix keeps junction slash",
			target:   "/files/a%2Fb",
			routeID:  "files-enc-upper",
			upstream: "http://upper.internal/up/",
		},
		{
			name:     "upper case encoded slash followed by a literal segment",
			target:   "/files/a%2Fb/x",
			routeID:  "files-enc-upper",
			upstream: "http://upper.internal/up/x",
		},
		{
			name:     "lower case encoded slash selects only the lower-case route",
			target:   "/files/a%2fb/y",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/y",
		},
		{
			name:     "lower case encoded slash, exact prefix",
			target:   "/files/a%2fb",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/",
		},
		{
			name:     "literal slash selects only the literal route",
			target:   "/files/a/b/x",
			routeID:  "files-literal",
			upstream: "http://literal.internal/li/x",
		},
		{
			name:     "literal slash, exact prefix",
			target:   "/files/a/b",
			routeID:  "files-literal",
			upstream: "http://literal.internal/li/",
		},
		{
			name:     "plain A route does not serve the percent-encoded request",
			target:   "/item/%41/x",
			routeID:  "item-encoded",
			upstream: "http://encoded.internal/e/x",
		},
		{
			name:     "percent encoded A route does not serve the plain request",
			target:   "/item/A/x",
			routeID:  "item-plain",
			upstream: "http://plain.internal/p/x",
		},
		{
			name:     "plain A exact and encoded A exact are separate matches",
			target:   "/item/%41",
			routeID:  "item-encoded",
			upstream: "http://encoded.internal/e/",
		},
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

	// A method not accepted by any of the spelling-specific routes falls to
	// the wildcard root even though the raw path hits one of their prefixes;
	// method filtering happens on raw matches, never on decoded-similar ones.
	res := resolveJSON(t, cfg, `{"method":"POST","target":"/files/a%2Fb/x"}`)
	if res.RouteID != "root" {
		t.Fatalf("routeId = %q, want root for POST against a GET-only prefix", res.RouteID)
	}
	if want := "https://fallback.internal/base/files/a%2Fb/x"; res.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

// TestResolveRawPrefixSegmentBoundaryAndFallback pins what happens just
// past a matching prefix: an encoded slash (either hex case) or an ordinary
// character continues the same segment and is not a hit, so such requests
// are served by the root route rather than any spelling-similar prefix.
func TestResolveRawPrefixSegmentBoundaryAndFallback(t *testing.T) {
	cfg := mustConfig(t, rawPrefixConfig)

	cases := []struct {
		name     string
		target   string
		upstream string
	}{
		{
			name:     "upper prefix extended by an upper-case encoded slash",
			target:   "/files/a%2Fb%2Fsecret",
			upstream: "https://fallback.internal/base/files/a%2Fb%2Fsecret",
		},
		{
			name:     "upper prefix extended by a lower-case encoded slash",
			target:   "/files/a%2Fb%2fsecret",
			upstream: "https://fallback.internal/base/files/a%2Fb%2fsecret",
		},
		{
			name:     "upper prefix extended by an ordinary character",
			target:   "/files/a%2Fbx",
			upstream: "https://fallback.internal/base/files/a%2Fbx",
		},
		{
			name:     "lower prefix extended by an ordinary character",
			target:   "/files/a%2fbox",
			upstream: "https://fallback.internal/base/files/a%2fbox",
		},
		{
			name:     "literal prefix extended by an ordinary character",
			target:   "/files/a/bx",
			upstream: "https://fallback.internal/base/files/a/bx",
		},
		{
			name:     "encoded item prefix extended by an ordinary character",
			target:   "/item/%41B",
			upstream: "https://fallback.internal/base/item/%41B",
		},
		{
			name:     "plain item prefix extended by an ordinary character",
			target:   "/item/AB",
			upstream: "https://fallback.internal/base/item/AB",
		},
		{
			name:     "an unrelated path keeps its raw encoding through the root",
			target:   "/ping?next=/files/a%2Fb",
			upstream: "https://fallback.internal/base/ping?next=/files/a%2Fb",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != "root" {
				t.Fatalf("routeId = %q, want root (no raw prefix hits on a segment boundary)", res.RouteID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}

	// Without a root route the same non-boundary (or simply uncovered)
	// targets must fail with route_not_found instead of succeeding.
	noRoot := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal"},
	  {"id":"enc","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://upper.internal/up"}
	]}`)
	for _, target := range []string{
		"/files/a%2Fb%2Fx", // encoded slash after the prefix is the same segment
		"/files/a%2Fbx",    // ordinary character after the prefix
		"/files/a/b/x",     // decoded-similar but raw-different prefix
		"/other",           // no matching prefix at all
	} {
		t.Run("no-root "+target, func(t *testing.T) {
			if _, rf := Resolve(noRoot, mustReq(t, "GET", target)); rf == nil || rf.Code != "route_not_found" {
				t.Fatalf("target %q: got %+v, want route_not_found", target, rf)
			}
		})
	}
}

// TestResolveRawPrefixQueryStringNeverAddsCandidates pins that matching
// sees only the path: a query string that happens to contain another
// route's complete prefix neither adds that route as a candidate nor
// turns a unique match into a conflict, and it is preserved verbatim on
// success.
func TestResolveRawPrefixQueryStringNeverAddsCandidates(t *testing.T) {
	cfg := mustConfig(t, rawPrefixConfig)

	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "encoded request with the plain prefix buried in the query",
			target:   "/item/%41?next=/item/A&also=/item/%2541",
			routeID:  "item-encoded",
			upstream: "http://encoded.internal/e/?next=/item/A&also=/item/%2541",
		},
		{
			name:     "plain request with the encoded prefix buried in the query",
			target:   "/item/A?next=/item/%41",
			routeID:  "item-plain",
			upstream: "http://plain.internal/p/?next=/item/%41",
		},
		{
			name:     "files prefixes named inside query values change nothing",
			target:   "/files/a%2fb/x?z=/files/a%2Fb&w=/files/a/b",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/x?z=/files/a%2Fb&w=/files/a/b",
		},
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

	// Two routes genuinely tied on the upper-case spelling conflict, but the
	// lower-case and literal routes named in the query must not join the
	// candidate set.
	conflictCfg := mustConfig(t, `{"routes":[
	  {"id":"zeta-upper","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://z.internal"},
	  {"id":"alpha-upper","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://a.internal"},
	  {"id":"only-lower","methods":["GET"],"pathPrefix":"/files/a%2fb","upstream":"http://l.internal"},
	  {"id":"only-literal","methods":["GET"],"pathPrefix":"/files/a/b","upstream":"http://t.internal"}
	]}`)
	_, rf := Resolve(conflictCfg, mustReq(t, "GET", "/files/a%2Fb?x=/files/a%2fb&y=/files/a/b"))
	if rf == nil || rf.Code != "route_conflict" {
		t.Fatalf("got %+v, want route_conflict", rf)
	}
	if want := []string{"alpha-upper", "zeta-upper"}; !equalStrings(rf.Candidates, want) {
		t.Fatalf("candidates = %v, want %v (query text and decoded-similar prefixes excluded)",
			rf.Candidates, want)
	}
}

// TestResolveRawPrefixLongestWinsAndMethodPrecedence checks the precedence
// rules are applied after raw matching, never instead of it: a longer raw
// prefix with a wildcard method beats a shorter prefix with a concrete
// method, concrete still beats wildcard on the same prefix, and a raw
// spelling the longer prefix does not carry falls back to the shorter
// prefix (or to route_not_found past a segment boundary).
func TestResolveRawPrefixLongestWinsAndMethodPrecedence(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"short-concrete","methods":["GET"],"pathPrefix":"/files",       "upstream":"http://short.internal/s"},
	  {"id":"long-wild",     "methods":["*"],  "pathPrefix":"/files/a%2Fb", "upstream":"http://wild.internal/w"},
	  {"id":"long-concrete", "methods":["GET"],"pathPrefix":"/files/a%2Fb", "upstream":"http://exact.internal/e"}
	]}`)

	cases := []struct {
		name     string
		method   string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "concrete GET on the longer prefix wins over both rivals",
			method:   "GET",
			target:   "/files/a%2Fb/x?a=1&a=",
			routeID:  "long-concrete",
			upstream: "http://exact.internal/e/x?a=1&a=",
		},
		{
			name:     "longer prefix exact match keeps the junction slash",
			method:   "GET",
			target:   "/files/a%2Fb",
			routeID:  "long-concrete",
			upstream: "http://exact.internal/e/",
		},
		{
			name:     "wildcard on the longer prefix beats the shorter concrete GET",
			method:   "POST",
			target:   "/files/a%2Fb/x",
			routeID:  "long-wild",
			upstream: "http://wild.internal/w/x",
		},
		{
			name:     "lower-case spelling only reaches the shorter prefix",
			method:   "GET",
			target:   "/files/a%2fb/x",
			routeID:  "short-concrete",
			upstream: "http://short.internal/s/a%2fb/x",
		},
		{
			name:     "an unrelated segment under /files uses the shorter prefix",
			method:   "GET",
			target:   "/files/z",
			routeID:  "short-concrete",
			upstream: "http://short.internal/s/z",
		},
		{
			name:     "encoded slash past the longer prefix falls back to the shorter prefix, raw bytes kept",
			method:   "GET",
			target:   "/files/a%2Fb%2Fx",
			routeID:  "short-concrete",
			upstream: "http://short.internal/s/a%2Fb%2Fx",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, `{"method":"`+tc.method+`","target":"`+tc.target+`"}`)
			if res.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", res.RouteID, tc.routeID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}

	// No boundary hit and no wildcard on the shorter prefix: not found.
	for _, tc := range []struct {
		method string
		target string
	}{
		{"GET", "/filesax"},    // "/files" followed by an ordinary character
		{"DELETE", "/files/z"}, // shorter prefix is GET-only
	} {
		t.Run("not-found "+tc.method+" "+tc.target, func(t *testing.T) {
			if _, rf := Resolve(cfg, mustReq(t, tc.method, tc.target)); rf == nil || rf.Code != "route_not_found" {
				t.Fatalf("got %+v, want route_not_found", rf)
			}
		})
	}

	// A config with only the longer prefix has nothing to fall back on when
	// the continuation is not a real segment boundary.
	longOnly := mustConfig(t, `{"routes":[
	  {"id":"long-wild","methods":["*"],"pathPrefix":"/files/a%2Fb","upstream":"http://wild.internal/w"}
	]}`)
	for _, target := range []string{"/files/a%2Fb%2Fx", "/files/a%2Fbx", "/files/a%2fb/x"} {
		t.Run("long-only not-found "+target, func(t *testing.T) {
			if _, rf := Resolve(longOnly, mustReq(t, "GET", target)); rf == nil || rf.Code != "route_not_found" {
				t.Fatalf("target %q: got %+v, want route_not_found", target, rf)
			}
		})
	}
}

// TestResolveRawPrefixConflictCandidatesBySpelling pins that a real tie is
// decided strictly among routes whose raw prefix hit: candidates come out in
// lexicographic id order, and routes whose prefix merely decodes to the same
// path (other slash spelling, other hex case, plain character vs encoding)
// are neither winners nor conflict candidates.
func TestResolveRawPrefixConflictCandidatesBySpelling(t *testing.T) {
	cfg := mustConfig(t, `{"routes":[
	  {"id":"zeta-upper",  "methods":["GET"], "pathPrefix":"/files/a%2Fb", "upstream":"http://z.internal"},
	  {"id":"alpha-upper", "methods":["GET"], "pathPrefix":"/files/a%2Fb", "upstream":"http://a.internal"},
	  {"id":"only-lower",  "methods":["GET"], "pathPrefix":"/files/a%2fb", "upstream":"http://l.internal"},
	  {"id":"only-literal","methods":["GET"], "pathPrefix":"/files/a/b",   "upstream":"http://t.internal"}
	]}`)

	_, rf := Resolve(cfg, mustReq(t, "GET", "/files/a%2Fb/x"))
	if rf == nil || rf.Code != "route_conflict" {
		t.Fatalf("got %+v, want route_conflict on the upper-case spelling", rf)
	}
	if want := []string{"alpha-upper", "zeta-upper"}; !equalStrings(rf.Candidates, want) {
		t.Fatalf("candidates = %v, want lexicographic %v", rf.Candidates, want)
	}

	// The other two spellings each resolve to their one route with no
	// success swallowed and no decoded-similar route mixed into a conflict.
	for _, tc := range []struct {
		target  string
		routeID string
	}{
		{"/files/a%2fb", "only-lower"},
		{"/files/a/b/x", "only-literal"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			res := resolveJSON(t, cfg, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != tc.routeID {
				t.Fatalf("routeId = %q, want %q (decoded-similar routes must not conflict)",
					res.RouteID, tc.routeID)
			}
		})
	}
}

// TestResolveRawPrefixStripsMatchedRawPrefixAndPreservesBytes pins the join
// on top of raw selection: the stripped text is exactly the raw prefix that
// hit, the remainder's percent escapes and hex case survive byte for byte,
// the unmodified query keeps duplicate parameters, empty values and order,
// and only the junction slash is normalized.
func TestResolveRawPrefixStripsMatchedRawPrefixAndPreservesBytes(t *testing.T) {
	cfg := mustConfig(t, rawPrefixConfig)

	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "remainder escapes and their hex case stay byte for byte",
			target:   "/files/a%2Fb/x%41Y%2fZ%2Fw",
			routeID:  "files-enc-upper",
			upstream: "http://upper.internal/up/x%41Y%2fZ%2Fw",
		},
		{
			name:     "the lower-case raw prefix is what gets stripped",
			target:   "/files/a%2fb/rem%41%2f",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/rem%41%2f",
		},
		{
			name:     "query duplicates, empty values and order are untouched",
			target:   "/files/a%2Fb/x?b=1&b=&flag&b=2&c=%2f",
			routeID:  "files-enc-upper",
			upstream: "http://upper.internal/up/x?b=1&b=&flag&b=2&c=%2f",
		},
		{
			name:     "bare question mark survives an exact-prefix match",
			target:   "/files/a%2fb?",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/?",
		},
		{
			name:     "no query stays distinct from an empty query",
			target:   "/files/a%2fb",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/",
		},
		{
			name:     "plain prefix strips the plain spelling and keeps encoded remainder",
			target:   "/files/a/b/keep%41%2Fnext?a=1&a=2",
			routeID:  "files-literal",
			upstream: "http://literal.internal/li/keep%41%2Fnext?a=1&a=2",
		},
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
}
