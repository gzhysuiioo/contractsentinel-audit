package contractsentinel

import (
	"encoding/json"
	"testing"
)

// Regression coverage for saving a parsed config with the standard library's
// JSON marshal and re-reading it through ParseConfig: the save must not
// change which routes compete for a request, turn an existing conflict into
// a success (or vice versa), or change a conflict into a config error. Every
// scenario resolves the request against both the parsed config and the
// saved-and-reparsed copy and requires the two full outcomes to match, so a
// save that drops, reorders or retypes a route shows up as a changed
// routeId/upstreamURL, a changed failure code or candidate list, or a
// flipped success/failure — never merely as a document that still parses.

// saveAndReload saves the config through Config.MarshalJSON and reads the
// output back through ParseConfig, failing the test if the saved document is
// rejected: a legal config must stay legal across the save.
func saveAndReload(t *testing.T, cfg *Config) *Config {
	t.Helper()
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	saved, f := ParseConfig(out)
	if f != nil {
		t.Fatalf("saved config rejected on re-read: %v\n%s", f, out)
	}
	return saved
}

// resolveOutcome is one full resolution result: exactly one of res/failure
// is non-nil.
type resolveOutcome struct {
	res     *Resolution
	failure *Failure
}

// resolveBeforeAndAfterSave resolves the same request against the parsed
// config and against its saved-and-reparsed copy, and requires the two
// outcomes to be identical: the same success routeId and upstreamURL, or the
// same failure code and candidate list. The reloaded config is what the
// "after" side resolves against, so the comparison exercises the saved
// document's routes, not the original ones.
func resolveBeforeAndAfterSave(t *testing.T, cfg *Config, method, target string) (before, after resolveOutcome) {
	t.Helper()
	saved := saveAndReload(t, cfg)
	req := mustReq(t, method, target)
	before.res, before.failure = Resolve(cfg, req)
	after.res, after.failure = Resolve(saved, req)

	switch {
	case before.failure == nil && after.failure == nil:
		if before.res.RouteID != after.res.RouteID || before.res.UpstreamURL != after.res.UpstreamURL {
			t.Fatalf("%s %s: resolution changed across save/reload:\n before %+v\n after  %+v",
				method, target, before.res, after.res)
		}
	case before.failure != nil && after.failure != nil:
		if before.failure.Code != after.failure.Code {
			t.Fatalf("%s %s: failure code changed across save/reload: %q -> %q",
				method, target, before.failure.Code, after.failure.Code)
		}
		if !equalStrings(before.failure.Candidates, after.failure.Candidates) {
			t.Fatalf("%s %s: candidates changed across save/reload: %v -> %v",
				method, target, before.failure.Candidates, after.failure.Candidates)
		}
	default:
		t.Fatalf("%s %s: save/reload flipped the outcome:\n before res=%+v failure=%+v\n after  res=%+v failure=%+v",
			method, target, before.res, before.failure, after.res, after.failure)
	}
	return before, after
}

// wantSuccess requires a successful resolution with exactly this route id
// and full upstream URL.
func wantSuccess(t *testing.T, o resolveOutcome, method, target, routeID, upstream string) {
	t.Helper()
	if o.failure != nil {
		t.Fatalf("%s %s: got failure %+v, want success %s / %s", method, target, o.failure, routeID, upstream)
	}
	if o.res == nil {
		t.Fatalf("%s %s: got no result at all, want success %s / %s", method, target, routeID, upstream)
	}
	if o.res.RouteID != routeID || o.res.UpstreamURL != upstream {
		t.Fatalf("%s %s: got %+v, want routeId %q upstreamURL %q", method, target, o.res, routeID, upstream)
	}
}

// wantConflict requires a route_conflict — never another code such as
// invalid_config — with a non-empty reason, exactly these candidates and no
// successful resolution alongside the failure.
func wantConflict(t *testing.T, o resolveOutcome, method, target string, candidates []string) {
	t.Helper()
	if o.res != nil {
		t.Fatalf("%s %s: got success %+v, want route_conflict %v", method, target, o.res, candidates)
	}
	if o.failure == nil {
		t.Fatalf("%s %s: got no failure, want route_conflict %v", method, target, candidates)
	}
	if o.failure.Code != "route_conflict" {
		t.Fatalf("%s %s: code = %q, want route_conflict (a request-stage conflict must not become another code such as invalid_config)",
			method, target, o.failure.Code)
	}
	if o.failure.Reason == "" {
		t.Fatalf("%s %s: route_conflict must carry a non-empty reason", method, target)
	}
	if !equalStrings(o.failure.Candidates, candidates) {
		t.Fatalf("%s %s: candidates = %v, want %v", method, target, o.failure.Candidates, candidates)
	}
}

func TestSaveReloadLongestPrefixBeatsShorterConcreteConflict(t *testing.T) {
	// Two concrete GET routes tied on the shorter prefix plus one wildcard
	// route on the longer prefix. A request inside the longer prefix must
	// select the wildcard route — the shorter-prefix tie must not reject it,
	// and a shorter-prefix concrete GET must not outrank the longer-prefix
	// wildcard — identically before and after the save.
	cfg := mustConfig(t, configFromRoutes(
		`{"id":"short-one","methods":["GET"],"pathPrefix":"/a","upstream":"http://one.internal/s1"}`,
		`{"id":"short-two","methods":["GET"],"pathPrefix":"/a","upstream":"http://two.internal/s2"}`,
		`{"id":"long-wild","methods":["*"],"pathPrefix":"/a/b","upstream":"http://wild.internal/base"}`,
	))

	// The query string carries duplicate parameters, an empty value and a
	// percent escape; with no queryTransforms on the route it must reach the
	// upstream URL verbatim on both sides of the save.
	target := "/a/b/c/items?keep=1&keep=2&empty=&x=%2f"
	before, after := resolveBeforeAndAfterSave(t, cfg, "GET", target)
	for _, o := range []resolveOutcome{before, after} {
		wantSuccess(t, o, "GET", target, "long-wild",
			"http://wild.internal/base/c/items?keep=1&keep=2&empty=&x=%2f")
	}

	// A request that only reaches the shorter prefix does hit the tie: it
	// must stay a route_conflict between exactly the two short-prefix GET
	// routes, before and after the save.
	before, after = resolveBeforeAndAfterSave(t, cfg, "GET", "/a/c")
	for _, o := range []resolveOutcome{before, after} {
		wantConflict(t, o, "GET", "/a/c", []string{"short-one", "short-two"})
	}
}

func TestSaveReloadConflictCandidatesStayFinalAndSorted(t *testing.T) {
	// Two concrete GET routes tied on the longest matching prefix, a
	// wildcard route on that same prefix and a concrete GET on a shorter
	// prefix. The two tied routes are listed out of lexicographic order so
	// the candidate list only comes out sorted if the existing sort rule
	// runs; the wildcard and shorter-prefix routes are already eliminated
	// and must never appear in the list.
	routes := []string{
		`{"id":"z-short","methods":["GET"],"pathPrefix":"/a","upstream":"http://short.internal"}`,
		`{"id":"wild-long","methods":["*"],"pathPrefix":"/a/b","upstream":"http://wild.internal/w"}`,
		`{"id":"zeta","methods":["GET"],"pathPrefix":"/a/b","upstream":"http://z.internal"}`,
		`{"id":"alpha","methods":["GET"],"pathPrefix":"/a/b","upstream":"http://a.internal"}`,
	}
	for _, order := range [][]string{routes, reversed(routes)} {
		cfg := mustConfig(t, configFromRoutes(order...))

		// GET stays a conflict between exactly the two concrete routes at
		// the longest prefix, candidates in lexicographic order, in either
		// route order and on both sides of the save.
		before, after := resolveBeforeAndAfterSave(t, cfg, "GET", "/a/b/x")
		for _, o := range []resolveOutcome{before, after} {
			wantConflict(t, o, "GET", "/a/b/x", []string{"alpha", "zeta"})
		}

		// POST has no concrete rival at the longest prefix, so the same
		// config must select the wildcard route there — the GET conflict
		// must not reject it — identically before and after the save.
		before, after = resolveBeforeAndAfterSave(t, cfg, "POST", "/a/b/x")
		for _, o := range []resolveOutcome{before, after} {
			wantSuccess(t, o, "POST", "/a/b/x", "wild-long", "http://wild.internal/w/x")
		}
	}
}
