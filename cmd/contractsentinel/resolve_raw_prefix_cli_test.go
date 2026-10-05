package main

// These tests exercise raw-encoded prefix matching the way a user does:
// one config file, one JSON request on stdin, and the observable
// exit status / stdout / stderr of the whole command — fully offline,
// with the upstream hosts never contacted. They pin the existing
// behavior that prefixes are matched on their original encoded spelling:
// decoded-equal prefixes with different raw bytes coexist and are chosen
// by the request's own spelling, "%2F"/"%2f" never open a new path
// segment, the query string never contributes a candidate, and a
// genuinely tied result is reported as route_conflict with lexicographic
// candidates while decoded-similar routes stay out of it.

import "testing"

// rawEncodedPrefixesConfig carries the three files spellings, the
// plain/encoded item pair and a wildcard root at once.
const rawEncodedPrefixesConfig = `{
  "routes": [
    {"id": "files-enc-upper", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://upper.internal/up"},
    {"id": "files-enc-lower", "methods": ["GET"], "pathPrefix": "/files/a%2fb", "upstream": "http://lower.internal/lo"},
    {"id": "files-literal",   "methods": ["GET"], "pathPrefix": "/files/a/b",   "upstream": "http://literal.internal/li"},
    {"id": "item-plain",      "methods": ["GET"], "pathPrefix": "/item/A",     "upstream": "http://plain.internal/p"},
    {"id": "item-encoded",    "methods": ["GET"], "pathPrefix": "/item/%41",   "upstream": "http://encoded.internal/e"},
    {"id": "root",            "methods": ["*"],   "pathPrefix": "/",           "upstream": "https://fallback.internal/base/"}
  ]
}`

// TestResolveCLIRawPrefixSpellingIsDistinct feeds the same config requests
// in each raw spelling and observes that only the route carrying that exact
// spelling is selected, with the remainder and query joined byte for byte.
func TestResolveCLIRawPrefixSpellingIsDistinct(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "upper case encoded slash exact",
			target:   "/files/a%2Fb",
			routeID:  "files-enc-upper",
			upstream: "http://upper.internal/up/",
		},
		{
			name:     "upper case encoded slash with a real next segment and raw remainder",
			target:   "/files/a%2Fb/x%41Y%2fz",
			routeID:  "files-enc-upper",
			upstream: "http://upper.internal/up/x%41Y%2fz",
		},
		{
			name:     "lower case request never selects the upper-case route",
			target:   "/files/a%2fb/y",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/y",
		},
		{
			name:     "literal slash request never selects an encoded-slash route",
			target:   "/files/a/b/x",
			routeID:  "files-literal",
			upstream: "http://literal.internal/li/x",
		},
		{
			name:     "plain A vs encoded A are separate routes",
			target:   "/item/%41/x",
			routeID:  "item-encoded",
			upstream: "http://encoded.internal/e/x",
		},
		{
			name:     "encoded A request never selects the plain A route",
			target:   "/item/A/x",
			routeID:  "item-plain",
			upstream: "http://plain.internal/p/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, rawEncodedPrefixesConfig, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}
}

// TestResolveCLIRawPrefixSegmentBoundaryAndFallback observes through the
// command boundary that an encoded slash (either case) or an ordinary
// character right after a prefix is not a segment boundary: such a request
// is served by the wildcard root, preserving its raw bytes, rather than by
// any decoded-similar prefix.
func TestResolveCLIRawPrefixSegmentBoundaryAndFallback(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"upper prefix extended by upper encoded slash", "/files/a%2Fb%2Fsecret"},
		{"upper prefix extended by lower encoded slash", "/files/a%2Fb%2fsecret"},
		{"upper prefix extended by an ordinary character", "/files/a%2Fbx"},
		{"lower prefix extended by an ordinary character", "/files/a%2fbox"},
		{"literal prefix extended by an ordinary character", "/files/a/bx"},
		{"encoded item prefix extended by an ordinary character", "/item/%41B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, rawEncodedPrefixesConfig, request))
			if success.RouteID != "root" {
				t.Fatalf("routeId = %q, want root (no raw prefix hit on a segment boundary)", success.RouteID)
			}
			if want := "https://fallback.internal/base" + tc.target; success.UpstreamURL != want {
				t.Fatalf("upstreamURL = %q, want %q", success.UpstreamURL, want)
			}
		})
	}

	// With no root route, the same targets are observable failures:
	// route_not_found on stderr, non-zero exit and an empty stdout rather
	// than any successful resolution.
	noRoot := `{"routes":[
	  {"id":"enc","methods":["GET"],"pathPrefix":"/files/a%2Fb","upstream":"http://upper.internal/up"}
	]}`
	for _, target := range []string{"/files/a%2Fb%2Fx", "/files/a%2Fbx", "/files/a/b/x"} {
		t.Run("not-found "+target, func(t *testing.T) {
			res := runResolveCLI(t, noRoot, `{"method":"GET","target":"`+target+`"}`)
			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero; stdout: %s", res.stdout)
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want empty on failure", res.stdout)
			}
			var fail struct {
				Code string `json:"code"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "route_not_found" {
				t.Fatalf("code = %q, want route_not_found", fail.Code)
			}
		})
	}
}

// TestResolveCLIRawPrefixQueryNeverAddsCandidates observes that a query
// string containing another route's full prefix neither changes selection
// nor introduces a conflict, and that duplicate parameters, empty values
// and order reach upstreamURL untouched.
func TestResolveCLIRawPrefixQueryNeverAddsCandidates(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "encoded path, plain prefix buried in the query",
			target:   "/item/%41?next=/item/A",
			routeID:  "item-encoded",
			upstream: "http://encoded.internal/e/?next=/item/A",
		},
		{
			name:     "plain path, encoded prefix buried in the query",
			target:   "/item/A?next=/item/%41&keep=1&keep=",
			routeID:  "item-plain",
			upstream: "http://plain.internal/p/?next=/item/%41&keep=1&keep=",
		},
		{
			name:     "files prefixes in query values leave selection untouched",
			target:   "/files/a%2fb/x?z=/files/a%2Fb&w=/files/a/b",
			routeID:  "files-enc-lower",
			upstream: "http://lower.internal/lo/x?z=/files/a%2Fb&w=/files/a/b",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, rawEncodedPrefixesConfig, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}
}

// TestResolveCLIRawPrefixConflictExcludesOtherSpellings ties two routes on
// the upper-case spelling while lower-case and literal routes exist too.
// The request on the upper-case spelling must fail with route_conflict and
// lexicographic candidates limited to the two upper-case routes; requests
// in the other spellings still resolve uniquely.
func TestResolveCLIRawPrefixConflictExcludesOtherSpellings(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "zeta-upper",  "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://z.internal"},
	    {"id": "alpha-upper", "methods": ["GET"], "pathPrefix": "/files/a%2Fb", "upstream": "http://a.internal"},
	    {"id": "only-lower",  "methods": ["GET"], "pathPrefix": "/files/a%2fb", "upstream": "http://l.internal"},
	    {"id": "only-literal","methods": ["GET"], "pathPrefix": "/files/a/b",   "upstream": "http://t.internal"}
	  ]
	}`

	// Conflict on the genuinely tied spelling; the query naming the other
	// spellings must not add candidates either.
	res := runResolveCLI(t, config,
		`{"method":"GET","target":"/files/a%2Fb/x?l=/files/a%2fb&t=/files/a/b"}`)
	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want empty on failure", res.stdout)
	}
	var fail struct {
		Code       string   `json:"code"`
		Candidates []string `json:"candidates"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "route_conflict" {
		t.Fatalf("code = %q, want route_conflict", fail.Code)
	}
	wantCandidates := []string{"alpha-upper", "zeta-upper"}
	if len(fail.Candidates) != len(wantCandidates) {
		t.Fatalf("candidates = %v, want %v", fail.Candidates, wantCandidates)
	}
	for i := range wantCandidates {
		if fail.Candidates[i] != wantCandidates[i] {
			t.Fatalf("candidates = %v, want lexicographic %v (other spellings excluded)",
				fail.Candidates, wantCandidates)
		}
	}

	// Other spellings resolve to their single route with no conflict.
	for _, tc := range []struct {
		target  string
		routeID string
	}{
		{"/files/a%2fb/y", "only-lower"},
		{"/files/a/b/y", "only-literal"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			success := assertResolveSuccess(t, runResolveCLI(t, config,
				`{"method":"GET","target":"`+tc.target+`"}`))
			if success.RouteID != tc.routeID {
				t.Fatalf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
		})
	}
}

// TestResolveCLIRawPrefixLongestWildcardBeatsShorterConcrete observes the
// precedence rule over raw spellings: a longer prefix carrying only the
// wildcard method wins over a shorter concrete-GET prefix, concrete still
// wins on the same prefix, and a spelling the longer prefix does not carry
// falls back to the shorter prefix rather than decoding.
func TestResolveCLIRawPrefixLongestWildcardBeatsShorterConcrete(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "short-concrete", "methods": ["GET"], "pathPrefix": "/files",       "upstream": "http://short.internal/s"},
	    {"id": "long-wild",      "methods": ["*"],  "pathPrefix": "/files/a%2Fb", "upstream": "http://wild.internal/w"},
	    {"id": "long-concrete",  "methods": ["GET"],"pathPrefix": "/files/a%2Fb", "upstream": "http://exact.internal/e"}
	  ]
	}`
	cases := []struct {
		name     string
		method   string
		target   string
		routeID  string
		upstream string
	}{
		{
			name:     "concrete GET wins on the longer prefix",
			method:   "GET",
			target:   "/files/a%2Fb/x?a=1&a=",
			routeID:  "long-concrete",
			upstream: "http://exact.internal/e/x?a=1&a=",
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"` + tc.method + `","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, config, request))
			if success.RouteID != tc.routeID {
				t.Errorf("routeId = %q, want %q", success.RouteID, tc.routeID)
			}
			if success.UpstreamURL != tc.upstream {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.upstream)
			}
		})
	}

	// A non-boundary continuation with no longer raw hit and no wildcard on
	// the shorter prefix fails as route_not_found.
	res := runResolveCLI(t, config, `{"method":"DELETE","target":"/files/z"}`)
	if res.exitCode == 0 || len(res.stdout) != 0 {
		t.Fatalf("got exit %d stdout %q, want non-zero exit and empty stdout", res.exitCode, res.stdout)
	}
	var fail struct {
		Code string `json:"code"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "route_not_found" {
		t.Fatalf("code = %q, want route_not_found", fail.Code)
	}
}
