package contractsentinel

import (
	"encoding/json"
	"sort"
	"testing"
)

// These tests guard conflict adjudication across the public save/reload
// path: a config parsed through ParseConfig is written with the standard
// library's encoding/json and read back through the same ParseConfig that
// production readers use, and the reloaded config is then actually used to
// resolve requests. Saving must not change which routes compete: a
// pre-save route_conflict may neither become a success nor flip to
// invalid_config, and a pre-save success must keep the same route id and
// the same fully-joined upstream URL (raw query included).
//
// Every scenario is exercised both before and after the save and with the
// routes declared in two orders, so candidate ordering in the saved output
// cannot mask a change in who competes.

// saveAndReparse runs one parsed config through the public save path:
// encoding/json marshals it the way an application saves it, and the
// existing ParseConfig reader parses the result. The saved document is a
// legal config rather than merely legal JSON; a re-read failure (in
// particular invalid_config) fails the test.
func saveAndReparse(t *testing.T, cfg *Config) *Config {
	t.Helper()
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	saved, f := ParseConfig(out)
	if f != nil {
		t.Fatalf("saved config rejected on re-read: %v\n%s", f, out)
	}
	return saved
}

// resolveOutcome is the complete observable result of one resolution:
// exactly one of res and fail is set.
type resolveOutcome struct {
	res  *Resolution
	fail *Failure
}

func resolveFor(t *testing.T, cfg *Config, method, target string) resolveOutcome {
	t.Helper()
	res, f := Resolve(cfg, mustReq(t, method, target))
	return resolveOutcome{res: res, fail: f}
}

// expectSuccess requires a resolution to succeed on the given config with
// exactly the expected route id and upstream URL. A conflict or any other
// failure — including a wrongly rejected config upstream of resolution —
// fails here.
func expectSuccess(t *testing.T, label, method, target, wantID, wantURL string, cfg *Config) {
	t.Helper()
	out := resolveFor(t, cfg, method, target)
	if out.fail != nil {
		t.Fatalf("%s: %s %s failed with %s: %s", label, method, target, out.fail.Code, out.fail.Reason)
	}
	if out.res == nil {
		t.Fatalf("%s: %s %s returned neither resolution nor failure", label, method, target)
	}
	if out.res.RouteID != wantID {
		t.Fatalf("%s: %s %s routeId = %q, want %q", label, method, target, out.res.RouteID, wantID)
	}
	if out.res.UpstreamURL != wantURL {
		t.Fatalf("%s: %s %s upstreamURL = %q, want %q", label, method, target, out.res.UpstreamURL, wantURL)
	}
}

// expectConflict requires route_conflict at request-resolution time (never
// invalid_config), a non-empty reason, no successful resolution and an
// exact, lexicographically sorted candidate list. An exact-list assertion
// also proves every route already eliminated by prefix length or
// concrete-vs-wildcard is absent.
func expectConflict(t *testing.T, label, method, target string, wantCandidates []string, cfg *Config) {
	t.Helper()
	out := resolveFor(t, cfg, method, target)
	if out.res != nil {
		t.Fatalf("%s: %s %s resolved to %+v, want route_conflict", label, method, target, out.res)
	}
	if out.fail == nil {
		t.Fatalf("%s: %s %s returned no failure, want route_conflict", label, method, target)
	}
	if out.fail.Code != "route_conflict" {
		t.Fatalf("%s: %s %s code = %q, want route_conflict (saving must not turn a request-stage conflict into a config error)",
			label, method, target, out.fail.Code)
	}
	if out.fail.Reason == "" {
		t.Fatalf("%s: %s %s route_conflict carries no reason", label, method, target)
	}
	if !equalStrings(out.fail.Candidates, wantCandidates) {
		t.Fatalf("%s: %s %s candidates = %v, want %v", label, method, target, out.fail.Candidates, wantCandidates)
	}
	if !sort.StringsAreSorted(out.fail.Candidates) {
		t.Fatalf("%s: %s %s candidates %v are not in lexicographic order", label, method, target, out.fail.Candidates)
	}
}

// assertSameOutcome fails unless two outcomes are the same kind of result
// with identical observable content, so the before/after comparison below
// is a complete equality check rather than two independent expectations.
func assertSameOutcome(t *testing.T, method, target string, before, after resolveOutcome) {
	t.Helper()
	switch {
	case before.fail != nil || after.fail != nil:
		if before.fail == nil || after.fail == nil {
			t.Fatalf("%s %s changed success/failure kind across save: before=%+v after=%+v",
				method, target, before.res, after.fail)
		}
		if before.fail.Code != after.fail.Code {
			t.Fatalf("%s %s error code changed across save: %q vs %q", method, target, before.fail.Code, after.fail.Code)
		}
		if !equalStrings(before.fail.Candidates, after.fail.Candidates) {
			t.Fatalf("%s %s candidates changed across save: %v vs %v",
				method, target, before.fail.Candidates, after.fail.Candidates)
		}
		if (before.fail.Reason == "") != (after.fail.Reason == "") {
			t.Fatalf("%s %s reason presence changed across save", method, target)
		}
	case before.res == nil || after.res == nil:
		t.Fatalf("%s %s missing a resolution on one side", method, target)
	default:
		if before.res.RouteID != after.res.RouteID || before.res.UpstreamURL != after.res.UpstreamURL {
			t.Fatalf("%s %s success changed across save:\n before %+v\n after  %+v",
				method, target, before.res, after.res)
		}
	}
}

func TestSaveRoundTripLongestWildcardBeatsShorterConflict(t *testing.T) {
	// Two concrete GET routes share the shorter prefix /a; one wildcard
	// route owns the longer prefix /a/b. Inside the longer prefix the
	// wildcard must win both before and after saving — the two short GET
	// routes must not reject the request as their conflict, and a concrete
	// GET on the shorter prefix must not outrank a wildcard on the longer
	// one. A request that reaches only /a must keep conflicting on exactly
	// the two short routes.
	routes := []string{
		`{"id":"short-one","methods":["GET"],"pathPrefix":"/a","upstream":"http://one.internal/s1"}`,
		`{"id":"short-two","methods":["GET"],"pathPrefix":"/a","upstream":"http://two.internal/s2"}`,
		`{"id":"long-wild","methods":["*"],"pathPrefix":"/a/b","upstream":"http://wild.internal/base"}`,
	}

	// Duplicate parameters, an empty value and percent escapes (including
	// an encoded '&' that must never split the query) survive both route
	// selection and the save.
	deepTarget := "/a/b/c/items?dup=1&dup=2&empty=&raw=%2f%41&%26=x"
	deepUpstream := "http://wild.internal/base/c/items?dup=1&dup=2&empty=&raw=%2f%41&%26=x"

	for _, order := range [][]string{routes, reversed(routes)} {
		cfg := mustConfig(t, configFromRoutes(order...))
		saved := saveAndReparse(t, cfg)

		// Direct expectations on both sides: candidate set, error code and
		// successful id/upstream all stay stable through the save.
		for _, v := range []struct {
			label string
			cfg   *Config
		}{
			{"before save", cfg},
			{"after save", saved},
		} {
			expectSuccess(t, v.label, "GET", deepTarget, "long-wild", deepUpstream, v.cfg)
			expectSuccess(t, v.label, "GET", "/a/b", "long-wild", "http://wild.internal/base/", v.cfg)
			// Same longer-prefix wildcard serves other methods too.
			expectSuccess(t, v.label, "POST", "/a/b/c", "long-wild", "http://wild.internal/base/c", v.cfg)
			// Only the short prefix matches: its two concrete GET routes
			// conflict, and the longer-prefix wildcard is not a candidate.
			expectConflict(t, v.label, "GET", "/a/only?z=1", []string{"short-one", "short-two"}, v.cfg)
		}

		// Whole-outcome equality is the actual save-regression assertion.
		for _, req := range []struct{ method, target string }{
			{"GET", deepTarget},
			{"GET", "/a/b"},
			{"POST", "/a/b/c"},
			{"GET", "/a/only?z=1"},
		} {
			assertSameOutcome(t, req.method, req.target,
				resolveFor(t, cfg, req.method, req.target),
				resolveFor(t, saved, req.method, req.target))
		}
	}
}

func TestSaveRoundTripConflictCandidatesStayExact(t *testing.T) {
	// The longest matching prefix /a/b carries two concrete GET routes and
	// a wildcard route; a shorter concrete GET route sits at /a. For a GET
	// request at /a/b the two concrete routes conflict: the saved config
	// must keep failing, list only those two routes sorted lexicographically,
	// and omit the already-excluded same-prefix wildcard and shorter-prefix
	// route. POST has no concrete rival at /a/b and must succeed on the
	// wildcard regardless of the GET conflict — both before and after saving.
	//
	// The routes are deliberately declared in an order different from
	// lexicographic (zeta before alpha), so a passing result proves the
	// existing sort rule rather than config order; the reversed slice
	// proves order independence again after the save.
	routes := []string{
		`{"id":"z-short","methods":["GET"],"pathPrefix":"/a","upstream":"http://short.internal"}`,
		`{"id":"wild-long","methods":["*"],"pathPrefix":"/a/b","upstream":"http://wild.internal/w"}`,
		`{"id":"zeta","methods":["GET"],"pathPrefix":"/a/b","upstream":"http://z.internal"}`,
		`{"id":"alpha","methods":["GET"],"pathPrefix":"/a/b","upstream":"http://a.internal"}`,
	}

	for _, order := range [][]string{routes, reversed(routes)} {
		cfg := mustConfig(t, configFromRoutes(order...))
		saved := saveAndReparse(t, cfg)

		for _, v := range []struct {
			label string
			cfg   *Config
		}{
			{"before save", cfg},
			{"after save", saved},
		} {
			// GET stays a request-stage conflict on exactly the two
			// concrete routes; the wildcard and the shorter route are gone.
			expectConflict(t, v.label, "GET", "/a/b/x", []string{"alpha", "zeta"}, v.cfg)

			// A method with no concrete competition wins the longest-prefix
			// wildcard; the GET conflict must not poison it.
			expectSuccess(t, v.label, "POST", "/a/b/x", "wild-long", "http://wild.internal/w/x", v.cfg)

			// The shorter-prefix concrete route still serves requests that
			// never reach the conflicted prefix.
			expectSuccess(t, v.label, "GET", "/a/other", "z-short", "http://short.internal/other", v.cfg)
		}

		for _, req := range []struct{ method, target string }{
			{"GET", "/a/b/x"},
			{"POST", "/a/b/x"},
			{"GET", "/a/other"},
		} {
			assertSameOutcome(t, req.method, req.target,
				resolveFor(t, cfg, req.method, req.target),
				resolveFor(t, saved, req.method, req.target))
		}
	}
}

func TestSaveRoundTripConflictDoesNotBecomeConfigError(t *testing.T) {
	// A focused guard for the specific regression shape named in the task:
	// resolving a legal request against a legal reloaded config must fail at
	// the request stage with route_conflict — never invalid_config — whether
	// or not the request carries a query string.
	cfg := mustConfig(t, configFromRoutes(
		`{"id":"short-one","methods":["GET"],"pathPrefix":"/a","upstream":"http://one.internal/s1"}`,
		`{"id":"short-two","methods":["GET"],"pathPrefix":"/a","upstream":"http://two.internal/s2"}`,
		`{"id":"long-wild","methods":["*"],"pathPrefix":"/a/b","upstream":"http://wild.internal/base"}`,
	))
	saved := saveAndReparse(t, cfg)

	for _, target := range []string{"/a/only", "/a/only?dup=1&dup=2&e=&p=%2f%41"} {
		out := resolveFor(t, saved, "GET", target)
		if out.res != nil {
			t.Fatalf("GET %s resolved to %+v after save, want route_conflict", target, out.res)
		}
		if out.fail == nil {
			t.Fatalf("GET %s produced no failure after save", target)
		}
		if out.fail.Code == "invalid_config" {
			t.Fatalf("GET %s became invalid_config (%s) after save; conflicts stay request-stage",
				target, out.fail.Reason)
		}
		if out.fail.Code != "route_conflict" {
			t.Fatalf("GET %s code = %q, want route_conflict", target, out.fail.Code)
		}
		if out.fail.Reason == "" {
			t.Fatalf("GET %s conflict has no reason after save", target)
		}
		if !equalStrings(out.fail.Candidates, []string{"short-one", "short-two"}) {
			t.Fatalf("GET %s candidates = %v after save, want [short-one short-two]",
				target, out.fail.Candidates)
		}
	}
}
