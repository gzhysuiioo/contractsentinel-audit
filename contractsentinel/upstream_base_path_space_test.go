package contractsentinel

import (
	"strings"
	"testing"
)

// This file pins the rule that an upstream base path must not carry a direct
// ASCII space (U+0020): "http://api.internal/base path" used to be accepted,
// and a hit route emitted an upstreamURL that still contained the space,
// even though the same byte in a request target is rejected as
// invalid_request. The space is judged on the address exactly as written —
// no trimming, no substitution with "%20" — while a percent-encoded space is
// legal path content that is never decoded first.

func TestInvalidConfigUpstreamBasePathDirectSpace(t *testing.T) {
	// A direct U+0020 anywhere in the base path — inside a segment, right
	// beside a slash or at the end of the path — rejects the whole config as
	// invalid_config. The reason locates the route by its 1-based position
	// and id and says the base path contains an unencoded space; it is an
	// address-content error, never broken config JSON.
	badUpstreams := []struct {
		name     string
		upstream string
	}{
		{"space inside a path segment", "http://api.internal/base path"},
		{"space right before a slash", "http://api.internal/base /path"},
		{"space right after a slash", "http://api.internal/base/ path"},
		{"space at the end of the base path", "http://api.internal/base "},
		{"space at the start of the base path", "http://api.internal/ base"},
		{"space in the first segment under https", "https://svc.internal/a b/c"},
		{"space beside a run of slashes", "http://h.internal/base /// path"},
	}
	for _, tc := range badUpstreams {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[
			  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
			  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"` + tc.upstream + `"}
			]}`
			cfg, f := ParseConfig([]byte(src))
			if f == nil {
				t.Fatalf("expected invalid_config for upstream %q, config was accepted", tc.upstream)
			}
			if f.Code != "invalid_config" {
				t.Fatalf("code = %q, want invalid_config", f.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "upstream", "unencoded space"} {
				if !strings.Contains(f.Reason, want) {
					t.Fatalf("reason = %q, want substring %q", f.Reason, want)
				}
			}
			for _, forbidden := range []string{"not valid JSON", "bracket", "missing a host"} {
				if strings.Contains(f.Reason, forbidden) {
					t.Fatalf("reason = %q must not say %q: a direct space is an address-content error",
						f.Reason, forbidden)
				}
			}
			if cfg != nil {
				t.Fatalf("a rejected config must not be returned, got %+v", cfg)
			}
		})
	}

	// The offending route may be the only route: validation fails while the
	// config is read, before any request reaches Resolve.
	src := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/base path"}]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	if !strings.Contains(f.Reason, "route 1") || !strings.Contains(f.Reason, `"api"`) {
		t.Fatalf("reason = %q, want route 1 and id \"api\"", f.Reason)
	}
	if cfg != nil {
		t.Fatal("a rejected config must not be returned")
	}

	// The same space written with JSON's \u0020 escape is still a literal
	// U+0020 once the JSON has been decoded, so the decoded address is judged
	// and rejected exactly like a literal space. The double-quoted
	// "\\u0020" piece below contributes the six JSON bytes backslash-u-0-0-2-0
	// — the escape a config file would hold — rather than a literal space.
	escaped := `{"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/base` +
		"\\u0020" + `path"}]}`
	if cfg2, f2 := ParseConfig([]byte(escaped)); f2 == nil || f2.Code != "invalid_config" {
		t.Fatalf("a JSON \\u0020 space must decode to a direct space and reject, got cfg=%+v f=%+v", cfg2, f2)
	} else if !strings.Contains(f2.Reason, "unencoded space") {
		t.Fatalf("reason = %q, want the unencoded-space reason", f2.Reason)
	}
}

func TestUpstreamBasePathSpaceRejectsEvenWhenAnotherRouteHits(t *testing.T) {
	// ParseConfig validates every route, so a later space-bearing upstream
	// rejects the whole configuration even though the request can only hit
	// the first, valid route: ParseConfig hands back no config at all and a
	// resolution against the earlier route is impossible.
	src := `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1"},
	  {"id":"admin","methods":["GET"],"pathPrefix":"/admin","upstream":"http://admin.internal/base path"}
	]}`
	cfg, f := ParseConfig([]byte(src))
	if f == nil || f.Code != "invalid_config" {
		t.Fatalf("got cfg=%+v f=%+v, want invalid_config", cfg, f)
	}
	for _, want := range []string{"route 2", `"admin"`, "unencoded space"} {
		if !strings.Contains(f.Reason, want) {
			t.Fatalf("reason = %q, want substring %q", f.Reason, want)
		}
	}
	if cfg != nil {
		t.Fatal("a rejected config must not be returned")
	}
}

func TestUpstreamBasePathEncodedSpaceStaysLegal(t *testing.T) {
	// A percent-encoded space is legal path content: it must not be decoded
	// first and then rejected, the route must match on its raw prefix, and
	// the base path, remainder and untouched query string reach upstreamURL
	// byte for byte. This is the headline spelling: prefix /api, upstream
	// "http://api.internal/base%20path", GET /api/items?x=%2f&x= joins to
	// "http://api.internal/base%20path/items?x=%2f&x=".
	cfg := mustConfig(t, `{"routes":[
	  {"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/base%20path"}
	]}`)
	got := resolveJSON(t, cfg, `{"method":"GET","target":"/api/items?x=%2f&x="}`)
	if got.RouteID != "api" {
		t.Fatalf("routeId = %q, want api", got.RouteID)
	}
	if want := "http://api.internal/base%20path/items?x=%2f&x="; got.UpstreamURL != want {
		t.Fatalf("upstreamURL = %q, want %q", got.UpstreamURL, want)
	}

	// Lowercase hex and an encoded space beside the junction survive too,
	// and the single-slash junction rule is unchanged.
	cases := []struct {
		name     string
		upstream string
		target   string
		want     string
	}{
		{"lowercase percent space in the base path", "http://h.internal/b%20ase", "/x", "http://h.internal/b%20ase/x"},
		{"encoded space ending the base path meets the junction", "http://h.internal/base%20", "/x", "http://h.internal/base%20/x"},
		{"two encoded spaces and an encoded slash kept raw", "http://h.internal/a%20b%20c%2Fd", "/x", "http://h.internal/a%20b%20c%2Fd/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mustConfig(t, `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"`+tc.upstream+`"}]}`)
			res := resolveJSON(t, c, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != "r" {
				t.Errorf("routeId = %q, want r", res.RouteID)
			}
			if res.UpstreamURL != tc.want {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.want)
			}
		})
	}
}

func TestUpstreamBasePathSpaceRuleOnlyTargetsDirectU0020(t *testing.T) {
	// The new check is confined to the direct ASCII space and must not expand
	// into a ban on all Unicode whitespace: an ideographic space U+3000 and a
	// no-break space U+00A0 in the base path keep their existing behavior
	// (url.Parse accepts them and the bytes join verbatim).
	cases := []struct {
		name     string
		upstream string
		target   string
		want     string
	}{
		{"ideographic space stays legal", "http://h.internal/base　p", "/x", "http://h.internal/base　p/x"},
		{"no break space stays legal", "http://h.internal/base p", "/x", "http://h.internal/base p/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"` + tc.upstream + `"}]}`
			c := mustConfig(t, src)
			res := resolveJSON(t, c, `{"method":"GET","target":"`+tc.target+`"}`)
			if res.RouteID != "r" {
				t.Errorf("routeId = %q, want r", res.RouteID)
			}
			if res.UpstreamURL != tc.want {
				t.Errorf("upstreamURL = %q, want %q", res.UpstreamURL, tc.want)
			}
		})
	}
}

func TestUpstreamBasePathMalformedEscapeKeepsExistingReason(t *testing.T) {
	// A malformed percent escape beside a space keeps its existing
	// url.Parse failure rather than being relabeled as an unencoded space,
	// mirroring the request side, where invalid percent escapes are reported
	// before direct-character checks.
	for _, upstream := range []string{
		"http://h.internal/base%2 0/x",
		"http://h.internal/base% 20/x",
	} {
		src := `{"routes":[{"id":"r","methods":["GET"],"pathPrefix":"/","upstream":"` + upstream + `"}]}`
		cfg, f := ParseConfig([]byte(src))
		if f == nil || f.Code != "invalid_config" {
			t.Fatalf("upstream %q: got cfg=%+v f=%+v, want invalid_config", upstream, cfg, f)
		}
		if !strings.Contains(f.Reason, "not a valid URL") {
			t.Fatalf("upstream %q: reason = %q, want the existing url.Parse failure", upstream, f.Reason)
		}
		if strings.Contains(f.Reason, "unencoded space") {
			t.Fatalf("upstream %q: a malformed escape must not be relabeled as a space error: %q", upstream, f.Reason)
		}
	}
}
