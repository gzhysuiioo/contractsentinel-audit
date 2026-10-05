package main

import (
	"strings"
	"testing"
)

// These tests drive the error-choice and error-location contract for config
// reading at the command boundary when several errors coexist in one config
// file. They pin the same precedence the package tests pin, but the way a user
// actually observes it: a config file argument, one JSON request on stdin, the
// exit status, completely empty stdout on failure, and exactly one JSON
// {code,reason} object on stderr. Everything runs offline — the upstreams are
// never contacted, so the cases reproduce deterministically on this machine.

// assertCLIInvalidConfig runs one resolve and requires the failure contract:
// non-zero exit, completely empty stdout and one JSON invalid_config error on
// stderr whose reason contains every want substring and none of forbidden.
// The request is the same one throughout: it matches the first route, proving
// an error on an unhit (or earlier-masked) route still rejects the read.
func assertCLIInvalidConfig(t *testing.T, config, request string, want, forbidden []string) {
	t.Helper()
	res := runResolveCLI(t, config, request)
	if res.exitCode == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if len(res.stdout) != 0 {
		t.Fatalf("stdout = %q, want completely empty on failure (no half result)", res.stdout)
	}
	var fail struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	decodeOneJSON(t, res.stderr, "stderr", &fail)
	if fail.Code != "invalid_config" {
		t.Fatalf("code = %q, want invalid_config", fail.Code)
	}
	for _, sub := range want {
		if !strings.Contains(fail.Reason, sub) {
			t.Fatalf("reason = %q, want substring %q", fail.Reason, sub)
		}
	}
	for _, sub := range forbidden {
		if strings.Contains(fail.Reason, sub) {
			t.Fatalf("reason = %q must not contain %q", fail.Reason, sub)
		}
	}
}

// The request matches the first ("api") route in every layered config below, so
// an error reported on a later route can never be explained away as "that route
// would have matched".
const precedenceRequest = `{"method":"GET","target":"/api/items?old=1&a=9&flag&keep=1"}`

// TestResolveCLIErrorPrecedenceAcrossLayers repairs one document a layer at a
// time and observes at the boundary which error surfaces after each repair:
//
//	methods type error -> unknown-op rule error -> pathPrefix content error ->
//	successful resolution (route selection, base-path join and query rewrite).
func TestResolveCLIErrorPrecedenceAcrossLayers(t *testing.T) {
	// Step 0: route 2 writes methods as a string (type); route 1 carries an
	// unknown op (rule); route 1's pathPrefix does not start with "/" (content).
	// The field type error wins and locates route 2 by position, carrying its
	// valid id even though the id is written after methods.
	step0 := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "api", "upstream": "http://api.internal/v1",
	     "queryTransforms": [{"op": "frob", "name": "a"}]},
	    {"methods": "GET", "id": "orders", "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	assertCLIInvalidConfig(t, step0, precedenceRequest,
		[]string{"route 2", `"orders"`, "methods must be an array of strings"},
		[]string{"queryTransforms rule", "frob", "pathPrefix must start with /", "not valid JSON"})

	// Step 1: repair methods. The route-1 unknown op surfaces with the 1-based
	// route position, id and rule index.
	step1 := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "api", "upstream": "http://api.internal/v1",
	     "queryTransforms": [{"op": "frob", "name": "a"}]},
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	assertCLIInvalidConfig(t, step1, precedenceRequest,
		[]string{"route 1", `"api"`, "queryTransforms rule 1", "unknown op"},
		[]string{"methods must be an array", "pathPrefix must start with /", "not valid JSON"})

	// Step 2: repair the rule into three valid rules. The content error
	// (pathPrefix not starting with "/") is what remains.
	step2 := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "api", "upstream": "http://api.internal/v1",
	     "queryTransforms": [
	       {"op": "set", "name": "a", "value": "1"},
	       {"op": "remove", "name": "flag"},
	       {"op": "rename", "name": "old", "to": "new"}
	     ]},
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	assertCLIInvalidConfig(t, step2, precedenceRequest,
		[]string{"route 1", `"api"`, "pathPrefix must start with /"},
		[]string{"queryTransforms rule", "unknown op", "not valid JSON"})

	// Step 3: repair the prefix. The same document now resolves; the matched
	// route's transforms rewrite the query in array order (set merges a to "1",
	// remove drops flag, rename moves old to new) while the join and the
	// surviving parameters keep their bytes and order.
	step3 := `{
	  "routes": [
	    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1",
	     "queryTransforms": [
	       {"op": "set", "name": "a", "value": "1"},
	       {"op": "remove", "name": "flag"},
	       {"op": "rename", "name": "old", "to": "new"}
	     ]},
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders", "upstream": "http://orders.internal"}
	  ]
	}`
	hitAPI := assertResolveSuccess(t, runResolveCLI(t, step3, precedenceRequest))
	if hitAPI.RouteID != "api" {
		t.Errorf("routeId = %q, want api", hitAPI.RouteID)
	}
	if want := "http://api.internal/v1/items?new=1&a=1&keep=1"; hitAPI.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", hitAPI.UpstreamURL, want)
	}

	// The longer-prefix second route wins for its own path. It defines no
	// transforms, so the raw query is preserved byte for byte.
	reqOrders := `{"method":"GET","target":"/api/orders/7?old=1&a=9&flag&a=2"}`
	hitOrders := assertResolveSuccess(t, runResolveCLI(t, step3, reqOrders))
	if hitOrders.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", hitOrders.RouteID)
	}
	if want := "http://orders.internal/7?old=1&a=9&flag&a=2"; hitOrders.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", hitOrders.UpstreamURL, want)
	}
}

// TestResolveCLIFieldTypeBeatsRuleRegardlessOfObjectOrder pins the headline
// rule at the boundary: route 2's methods-as-a-string type error is reported
// ahead of route 1's unknown op, the reason carries route 2's id wherever the
// id sits in the object, and reordering the object's uniquely-named fields
// cannot change the result.
func TestResolveCLIFieldTypeBeatsRuleRegardlessOfObjectOrder(t *testing.T) {
	route1 := `{"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://a",
	     "queryTransforms": [{"op": "frob", "name": "a"}]}`

	route2Variants := []string{
		`{"methods": "GET", "id": "orders", "pathPrefix": "/api/orders", "upstream": "http://o"}`,
		`{"id": "orders", "methods": "GET", "pathPrefix": "/api/orders", "upstream": "http://o"}`,
		`{"upstream": "http://o", "pathPrefix": "/api/orders", "methods": "GET", "id": "orders"}`,
	}
	for _, route2 := range route2Variants {
		config := `{"routes": [` + route1 + `,` + route2 + `]}`
		assertCLIInvalidConfig(t, config, precedenceRequest,
			[]string{"route 2", `"orders"`, "methods must be an array of strings"},
			[]string{"queryTransforms rule", "frob", "route 1", "not valid JSON"})
	}
}

// TestResolveCLIRuleErrorEarliestByArrayPosition pins that rule-error
// selection follows array position, not id lexicographic order: the route
// first in the routes array and, within it, the rule first in the
// queryTransforms array is named.
func TestResolveCLIRuleErrorEarliestByArrayPosition(t *testing.T) {
	// "zzz" sorts after "aaa" but is first in the array.
	byRoute := `{
	  "routes": [
	    {"id": "zzz", "methods": ["GET"], "pathPrefix": "/z", "upstream": "http://h",
	     "queryTransforms": [{"op": "frob", "name": "z"}]},
	    {"id": "aaa", "methods": ["GET"], "pathPrefix": "/a", "upstream": "http://h",
	     "queryTransforms": [{"op": "frob", "name": "a"}]}
	  ]
	}`
	assertCLIInvalidConfig(t, byRoute, precedenceRequest,
		[]string{"route 1", `"zzz"`, "queryTransforms rule 1", "unknown op"},
		[]string{`"aaa"`, "route 2"})

	// Rule 3 on the first route beats rule 1 on the second.
	byRule := `{
	  "routes": [
	    {"id": "a", "methods": ["GET"], "pathPrefix": "/a", "upstream": "http://h",
	     "queryTransforms": [
	       {"op": "set", "name": "a", "value": "1"},
	       {"op": "remove", "name": "b"},
	       {"op": "frob", "name": "c"}
	     ]},
	    {"id": "b", "methods": ["GET"], "pathPrefix": "/b", "upstream": "http://h",
	     "queryTransforms": [{"op": "frob", "name": "z"}]}
	  ]
	}`
	assertCLIInvalidConfig(t, byRule, precedenceRequest,
		[]string{"route 1", `"a"`, "queryTransforms rule 3", "unknown op"},
		[]string{"queryTransforms rule 1", `"b"`, "route 2"})
}

// TestResolveCLIBrokenConfigJSONGuessesNothing pins the syntax layer at the
// boundary: a document whose JSON grammar is broken — even after a complete
// first route — is only ever a parse failure, with no guessed field, route or
// rule position, non-zero exit and empty stdout.
func TestResolveCLIBrokenConfigJSONGuessesNothing(t *testing.T) {
	broken := []string{
		`{"routes":[{"id":"x","methods":["GET"],"pathPrefix":"/a","upstream":"http://h"} BROKEN`,
		`{"routes":[ BROKEN`,
	}
	for _, config := range broken {
		res := runResolveCLI(t, config, precedenceRequest)
		if res.exitCode == 0 {
			t.Fatalf("exit code = 0, want non-zero for %q", config)
		}
		if len(res.stdout) != 0 {
			t.Fatalf("stdout = %q, want completely empty", res.stdout)
		}
		var fail struct {
			Code   string `json:"code"`
			Reason string `json:"reason"`
		}
		decodeOneJSON(t, res.stderr, "stderr", &fail)
		if fail.Code != "invalid_config" || !strings.Contains(fail.Reason, "not valid JSON") {
			t.Fatalf("got %+v, want invalid_config parse failure", fail)
		}
		for _, guessed := range []string{"route 1", "route 2", "queryTransforms rule", "methods", "routes must"} {
			if strings.Contains(fail.Reason, guessed) {
				t.Fatalf("parse failure must not guess %q: %q", guessed, fail.Reason)
			}
		}
	}
}
