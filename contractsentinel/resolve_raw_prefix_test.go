package contractsentinel

import (
	"strings"
	"testing"
)

// These tests pin the raw-encoded prefix matching contract: a configured
// pathPrefix is matched against the request path byte for byte, exactly as
// written. Prefixes that would decode to the same path but are spelled
// differently — "/files/a%2Fb" vs "/files/a%2fb" vs "/files/a/b", or
// "/item/A" vs "/item/%41" — are different routes, and a request selects
// only the route whose raw spelling its own raw path hits. Matching never
// decodes the path and never normalizes the case of percent escapes, the
// query string never contributes candidates, and a "%2F" (either case)
// directly after a prefix is the same segment continuing, not a separator.

// rawPrefixConfig holds three routes whose prefixes all decode to
// "/files/a/b" but are spelled three different ways, plus a root fallback.
const rawPrefixConfig = `{
  "routes": [
    {"id": "enc-upper", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://upper.internal/u"},
    {"id": "enc-lower", "methods": ["GET"], "pathPrefix": "/files/a%2fb", "upstream": "http://lower.internal/l"},
    {"id": "plain",     "methods": ["GET"], "pathPrefix": "/files/a/b",   "upstream": "http://plain.internal/p"},
    {"id": "root",      "methods": ["*"],   "pathPrefix": "/",            "upstream": "http://fallback.internal/base"}
  ]
}`

func TestResolveRawEncodedPrefixSelectedVerbatim(t *testing.T) {
	// One legal config carries all three spellings at once. Each request is
	// served only by the route its raw path spelling hits; decoding the path
	// or unifying the escape case would merge the three routes into one and
	// must never change the selection.
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "uppercase escape selects the uppercase route",
			target:   "/files/a%2Fb/x",
			routeID:  "enc-upper",
			upstream: "http://upper.internal/u/x",
		},
		{
			name:     "lowercase escape selects the lowercase route",
			target:   "/files/a%2fb/x",
			routeID:  "enc-lower",
			upstream: "http://lower.internal/l/x",
		},
		{
			name:     "literal slash selects the plain route",
			target:   "/files/a/b/x",
			routeID:  "plain",
			upstream: "http://plain.internal/p/x",
		},
		{
			name:     "exact uppercase prefix keeps one junction slash",
			target:   "/files/a%2Fb",
			routeID:  "enc-upper",
			upstream: "http://upper.internal/u/",
		},
		{
			name:     "exact lowercase prefix keeps one junction slash",
			target:   "/files/a%2fb",
			routeID:  "enc-lower",
			upstream: "http://lower.internal/l/",
		},
		{
			name:     "exact plain prefix keeps one junction slash",
			target:   "/files/a/b",
			routeID:  "plain",
			upstream: "http://plain.internal/p/",
		},
	}
	cfg := mustConfig(t, rawPrefixConfig)
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

func TestResolveEncodedCharVsLiteralPrefix(t *testing.T) {
	// The same raw-spelling rule applies to an ordinary character and its
	// percent-encoded form: "/item/A" and "/item/%41" decode to the same
	// path but are configured as separate routes, and each serves only the
	// requests written its way.
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "literal", "methods": ["GET"], "pathPrefix": "/item/A",   "upstream": "http://literal.internal/a"},
	    {"id": "encoded", "methods": ["GET"], "pathPrefix": "/item/%41", "upstream": "http://encoded.internal/e"}
	  ]
	}`)
	cases := []struct {
		target   string
		routeID  string
		upstream string
	}{
		{"/item/A/1", "literal", "http://literal.internal/a/1"},
		{"/item/%41/1", "encoded", "http://encoded.internal/e/1"},
		{"/item/A", "literal", "http://literal.internal/a/"},
		{"/item/%41", "encoded", "http://encoded.internal/e/"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
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

func TestResolveQueryStringNeverAddsCandidates(t *testing.T) {
	// Matching looks at the raw path only. A query parameter whose content
	// is another route's complete prefix — raw, encoded or doubly encoded —
	// must not pull that route into the candidate set, and the query itself
	// is carried to the upstream byte for byte.
	cfg := mustConfig(t, rawPrefixConfig)

	res := resolveJSON(t, cfg,
		`{"method":"GET","target":"/files/a/b?next=/files/a%2Fb/x&enc=%2Ffiles%2Fa%252Fb&empty="}`)
	if res.RouteID != "plain" {
		t.Errorf("routeId = %q, want plain (query content is not a candidate)", res.RouteID)
	}
	want := "http://plain.internal/p/?next=/files/a%2Fb/x&enc=%2Ffiles%2Fa%252Fb&empty="
	if res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}

	// A path no configured prefix matches falls to the root route even when
	// the query holds a route's full prefix.
	res = resolveJSON(t, cfg, `{"method":"GET","target":"/other?redirect=/files/a%2Fb"}`)
	if res.RouteID != "root" {
		t.Errorf("routeId = %q, want root", res.RouteID)
	}
	if want := "http://fallback.internal/base/other?redirect=/files/a%2Fb"; res.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestResolveEncodedSlashIsNotSegmentBoundary(t *testing.T) {
	// A prefix hits only when the path equals it or continues with a literal
	// '/'. A "%2F" or "%2f" right after the prefix bytes is the same segment
	// continuing, never a new separator, and an ordinary following character
	// is not a boundary either; such requests fall through to any shorter
	// prefix that does hit on a real boundary.
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "enc",   "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://enc.internal/e"},
	    {"id": "files", "methods": ["GET"], "pathPrefix": "/files",       "upstream": "http://files.internal/f"}
	  ]
	}`)
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "encoded slash after the prefix continues the segment",
			target:   "/files/a%2Fb%2Fc/x",
			routeID:  "files",
			upstream: "http://files.internal/f/a%2Fb%2Fc/x",
		},
		{
			name:     "lowercase encoded slash after the prefix continues the segment",
			target:   "/files/a%2Fb%2fc/x",
			routeID:  "files",
			upstream: "http://files.internal/f/a%2Fb%2fc/x",
		},
		{
			name:     "ordinary character after the prefix is not a boundary",
			target:   "/files/a%2Fbx/y",
			routeID:  "files",
			upstream: "http://files.internal/f/a%2Fbx/y",
		},
		{
			name:     "literal slash after the prefix is a boundary",
			target:   "/files/a%2Fb/y",
			routeID:  "enc",
			upstream: "http://enc.internal/e/y",
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

func TestResolveRawPrefixNotFoundWithoutFallback(t *testing.T) {
	// Without a root route, a request whose raw spelling hits no configured
	// prefix yields route_not_found and no success result — decoding the
	// path to find a candidate is not allowed, and neither is unifying the
	// escape case.
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "enc", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://enc.internal/e"}
	  ]
	}`)
	for _, target := range []string{
		"/files/a/b/x",   // literal slashes decode to the prefix but are spelled differently
		"/files/a%2fb/x", // only the escape's case differs
	} {
		res, rf := Resolve(cfg, mustReq(t, "GET", target))
		if res != nil {
			t.Fatalf("%s: got success %+v, want route_not_found", target, res)
		}
		if rf == nil || rf.Code != "route_not_found" {
			t.Fatalf("%s: got %+v, want route_not_found", target, rf)
		}
	}
}

func TestResolveRawPrefixPrecedenceRules(t *testing.T) {
	// The precedence rules are unchanged by encoded spellings: the longest
	// matching raw prefix wins even when a shorter prefix names the concrete
	// method and the longer one is a wildcard, and among routes tied on the
	// same longest prefix a concrete method still beats the wildcard.
	routes := []string{
		`{"id":"short-get","methods":["GET"],"pathPrefix":"/files","upstream":"http://short.internal/s"}`,
		`{"id":"long-wild","methods":["*"],"pathPrefix":"/files/a%2Fb","upstream":"http://wild.internal/w"}`,
		`{"id":"long-get","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://exact.internal/e"}`,
	}
	for _, order := range [][]string{routes, reversed(routes)} {
		cfg := mustConfig(t, configFromRoutes(order...))

		res := resolveJSON(t, cfg, `{"method":"GET","target":"/files/a%2Fb/x"}`)
		if res.RouteID != "long-get" || res.UpstreamURL != "http://exact.internal/e/x" {
			t.Fatalf("GET: got %+v, want long-get / http://exact.internal/e/x", res)
		}

		// No concrete entry for POST at the longest prefix: the wildcard
		// there still beats the shorter prefix's concrete GET-only route.
		res = resolveJSON(t, cfg, `{"method":"POST","target":"/files/a%2Fb/x"}`)
		if res.RouteID != "long-wild" || res.UpstreamURL != "http://wild.internal/w/x" {
			t.Fatalf("POST: got %+v, want long-wild / http://wild.internal/w/x", res)
		}

		// A request that never reaches the encoded prefix is served by the
		// shorter route as before.
		res = resolveJSON(t, cfg, `{"method":"GET","target":"/files/other"}`)
		if res.RouteID != "short-get" || res.UpstreamURL != "http://short.internal/s/other" {
			t.Fatalf("GET /files/other: got %+v, want short-get", res)
		}
	}
}

func TestResolveRawPrefixConflictExcludesDecodedLookalikes(t *testing.T) {
	// Two routes tied on the identical raw prefix conflict, with candidate
	// ids in lexicographic order. Routes whose prefixes merely decode to the
	// same path — the lowercase-escape and the literal-slash spellings — did
	// not match the raw request path and must not appear among the
	// candidates, and the same-prefix wildcard is already eliminated.
	routes := []string{
		`{"id":"zeta","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://z.internal"}`,
		`{"id":"alpha","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://a.internal"}`,
		`{"id":"wild","methods":["*"],"pathPrefix":"/files/a%2Fb","upstream":"http://w.internal"}`,
		`{"id":"lower","methods":["GET"],"pathPrefix":"/files/a%2fb","upstream":"http://l.internal"}`,
		`{"id":"plain","methods":["GET"],"pathPrefix":"/files/a/b","upstream":"http://p.internal"}`,
	}
	for _, order := range [][]string{routes, reversed(routes)} {
		cfg := mustConfig(t, configFromRoutes(order...))

		res, rf := Resolve(cfg, mustReq(t, "GET", "/files/a%2Fb/x"))
		if res != nil {
			t.Fatalf("got success %+v, want route_conflict", res)
		}
		if rf == nil || rf.Code != "route_conflict" {
			t.Fatalf("got %+v, want route_conflict", rf)
		}
		if want := []string{"alpha", "zeta"}; !equalStrings(rf.Candidates, want) {
			t.Fatalf("candidates = %v, want %v (no wildcard, no decoded lookalikes)", rf.Candidates, want)
		}

		// The lowercase spelling resolves on its own with no conflict: only
		// the one raw-matching route is ever a candidate for it.
		res = resolveJSON(t, cfg, `{"method":"GET","target":"/files/a%2fb/x"}`)
		if res.RouteID != "lower" {
			t.Fatalf("lowercase request: routeId = %q, want lower", res.RouteID)
		}
	}
}

func TestResolveRawPrefixRemainderAndQueryPreserved(t *testing.T) {
	// After the raw prefix is selected, exactly those raw prefix bytes are
	// stripped and the remainder is joined onto the upstream base path.
	// Percent escapes in the remainder keep their spelling and case, the
	// unrewritten query keeps duplicate parameters, empty values and order,
	// and only the junction slash run is collapsed.
	cfg := mustConfig(t, `{
	  "routes": [
	    {"id": "enc", "methods": ["GET"], "pathPrefix": "/files/a%2Fb",
	     "upstream": "http://enc.internal/base%2f//"}
	  ]
	}`)
	cases := []struct {
		name     string
		target   string
		upstream string
	}{
		{
			name:     "remainder escapes keep their case, query stays verbatim",
			target:   "/files/a%2Fb/%41%2fZ//tail?b=1&b=&flag&b=2",
			upstream: "http://enc.internal/base%2f/%41%2fZ//tail?b=1&b=&flag&b=2",
		},
		{
			name:     "exact prefix collapses the base's trailing slashes to one",
			target:   "/files/a%2Fb?x=%2F",
			upstream: "http://enc.internal/base%2f/?x=%2F",
		},
		{
			name:     "empty query marker survives the join",
			target:   "/files/a%2Fb/deep%2F?",
			upstream: "http://enc.internal/base%2f/deep%2F?",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolveJSON(t, cfg, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != "enc" {
				t.Errorf("routeId = %q, want enc", res.RouteID)
			}
			if res.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.upstream)
			}
		})
	}
}

// TestResolveRawPrefixConfigStaysValid pins that the three spellings are one
// legal configuration: validation rejects duplicates by id, never by
// decoded-prefix equality, so the routes coexist and keep their order.
func TestResolveRawPrefixConfigStaysValid(t *testing.T) {
	cfg := mustConfig(t, rawPrefixConfig)
	if len(cfg.Routes) != 4 {
		t.Fatalf("routes = %d, want 4", len(cfg.Routes))
	}
	var prefixes []string
	for _, r := range cfg.Routes {
		prefixes = append(prefixes, r.PathPrefix)
	}
	want := []string{"/files/a%2Fb", "/files/a%2fb", "/files/a/b", "/"}
	if strings.Join(prefixes, ",") != strings.Join(want, ",") {
		t.Fatalf("prefixes = %v, want %v (raw spellings preserved, order kept)", prefixes, want)
	}
}
