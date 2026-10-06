package main

import (
	"strings"
	"testing"
)

// These tests pin the copy query transform at the resolve command boundary:
// the rule is read from the config file's queryTransforms, one JSON request
// arrives on stdin, and the copied query is observed inside the emitted
// routeId and upstreamURL. Everything runs offline — the upstream hosts
// never need to exist.

// TestResolveCLICopyQueryTransform drives the headline copy behavior the way
// a user does. Every source parameter keeps its place and gains a copy
// immediately after itself; the pre-existing new=9 stays where it was and is
// neither merged nor overwritten. Sources are recognized by decoded name
// ("%6Fld" is "old"), the source's own name encoding is left alone, and the
// empty value keeps its '=' while the valueless source gains a valueless
// copy — the two forms stay distinct.
func TestResolveCLICopyQueryTransform(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
	     "upstream": "http://orders.internal",
	     "queryTransforms": [{"op": "copy", "name": "old", "to": "new"}]}
	  ]
	}`
	request := `{"method":"GET","target":"/api/orders/7?old=%2f+&new=9&%6Fld=&old"}`

	success := assertResolveSuccess(t, runResolveCLI(t, config, request))
	if success.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", success.RouteID)
	}
	wantURL := "http://orders.internal/7?old=%2f+&new=%2f+&new=9&%6Fld=&new=&old&new"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLICopyValueBytesAndUnmatchedFragments checks at the command
// boundary that a copy duplicates the first '=' and everything after it byte
// for byte — percent-escape case, '+' and extra '=' included — while
// parameters that do not hit and empty fragments keep their original content
// and order.
func TestResolveCLICopyValueBytesAndUnmatchedFragments(t *testing.T) {
	rootConfig := func(rule string) string {
		return `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
			`"upstream":"http://h.internal/base","queryTransforms":[` + rule + `]}]}`
	}
	cases := []struct {
		name    string
		rule    string
		target  string
		wantURL string
	}{
		{
			name:    "value bytes copied verbatim",
			rule:    `{"op":"copy","name":"old","to":"new"}`,
			target:  "/p?old=%2f+%2F+a=b&x=1",
			wantURL: "http://h.internal/base/p?old=%2f+%2F+a=b&new=%2f+%2F+a=b&x=1",
		},
		{
			name:    "unmatched parameters and empty fragments keep content and order",
			rule:    `{"op":"copy","name":"old","to":"new"}`,
			target:  "/p?a=1&&old=2&&",
			wantURL: "http://h.internal/base/p?a=1&&old=2&new=2&&",
		},
		{
			name:    "no source parameter leaves the query byte for byte",
			rule:    `{"op":"copy","name":"old","to":"new"}`,
			target:  "/p?a=1&%62=2",
			wantURL: "http://h.internal/base/p?a=1&%62=2",
		},
		{
			name:    "same source and target name makes no copies and re-encodes nothing",
			rule:    `{"op":"copy","name":"a b","to":"a b"}`,
			target:  "/p?a+b=1&a%20b=2&x=",
			wantURL: "http://h.internal/base/p?a+b=1&a%20b=2&x=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			success := assertResolveSuccess(t, runResolveCLI(t, rootConfig(tc.rule),
				`{"method":"GET","target":"`+tc.target+`"}`))
			if success.RouteID != "root" {
				t.Errorf("routeId = %q, want root", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.wantURL)
			}
		})
	}
}

// TestResolveCLICopyThenRemoveKeepsCopies pins rule ordering through the CLI:
// after old is copied to new, removing old deletes only the source
// parameters — the copies and the pre-existing new parameter survive, each
// in its own position.
func TestResolveCLICopyThenRemoveKeepsCopies(t *testing.T) {
	config := `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",
	  "upstream":"http://h.internal/base",
	  "queryTransforms":[
	    {"op":"copy","name":"old","to":"new"},
	    {"op":"remove","name":"old"}
	  ]}]}`
	success := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"GET","target":"/p?old=1&new=9&x=3&old=2"}`))
	if success.RouteID != "root" {
		t.Errorf("routeId = %q, want root", success.RouteID)
	}
	wantURL := "http://h.internal/base/p?new=1&new=9&x=3&new=2"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
}

// TestResolveCLICopyOnlyOnSelectedRoute proves the copy belongs to the
// finally matched route: it neither changes prefix selection nor upstream
// base-path joining, and a losing route's copy is never executed.
func TestResolveCLICopyOnlyOnSelectedRoute(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "wide", "methods": ["*"], "pathPrefix": "/api",
	     "upstream": "http://wide.internal/w",
	     "queryTransforms": [{"op": "copy", "name": "old", "to": "wide"}]},
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
	     "upstream": "http://orders.internal",
	     "queryTransforms": [{"op": "copy", "name": "old", "to": "new"}]}
	  ]
	}`

	// GET /api/orders/7 selects the longer concrete route; the wildcard
	// route's old->wide copy must not touch the query, and the /7 join onto
	// a host-only upstream is unchanged.
	longer := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"GET","target":"/api/orders/7?old=1&new=9&old"}`))
	if longer.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders (longest prefix wins)", longer.RouteID)
	}
	if want := "http://orders.internal/7?old=1&new=1&new=9&old&new"; longer.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", longer.UpstreamURL, want)
	}

	// A request only the wide route matches runs that route's own copy and
	// joins onto its base path normally.
	wide := assertResolveSuccess(t, runResolveCLI(t, config,
		`{"method":"POST","target":"/api/x?old=1"}`))
	if wide.RouteID != "wide" {
		t.Errorf("routeId = %q, want wide", wide.RouteID)
	}
	if want := "http://wide.internal/w/x?old=1&wide=1"; wide.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", wide.UpstreamURL, want)
	}
}

// TestResolveCLICopyInvalidToRejectsConfig exercises the copy boundary at
// the command boundary: a missing or empty "to" invalidates the whole
// configuration even though the offending route can never match the request.
// Failure exits non-zero, leaves stdout completely empty and puts one JSON
// error on stderr whose reason says copy requires a non-empty string to and
// names the 1-based route position, the route's id and the 1-based rule
// index.
func TestResolveCLICopyInvalidToRejectsConfig(t *testing.T) {
	cases := []struct {
		name       string
		bad        string
		wantReason string
	}{
		{"to missing", `{"op":"copy","name":"a"}`, "copy requires a non-empty string to"},
		{"to empty", `{"op":"copy","name":"a","to":""}`, "to must be a non-empty string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Route 1 ("hit") serves every request via the root prefix;
			// route 2 ("admin") never matches. A valid set rule precedes
			// the bad copy, pinning the reported location to rule 2.
			config := `{
			  "routes": [
			    {"id": "hit", "methods": ["*"], "pathPrefix": "/",
			     "upstream": "http://hit.internal"},
			    {"id": "admin", "methods": ["GET"], "pathPrefix": "/admin",
			     "upstream": "http://admin.internal",
			     "queryTransforms": [
			       {"op": "set", "name": "a", "value": "1"},
			       ` + tc.bad + `
			     ]}
			  ]
			}`
			res := runResolveCLI(t, config, `{"method":"GET","target":"/ping?old=1"}`)

			if res.exitCode == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if len(res.stdout) != 0 {
				t.Fatalf("stdout = %q, want completely empty on failure", res.stdout)
			}
			var fail struct {
				Code   string `json:"code"`
				Reason string `json:"reason"`
			}
			decodeOneJSON(t, res.stderr, "stderr", &fail)
			if fail.Code != "invalid_config" {
				t.Errorf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{
				"route 2", `"admin"`, "rule 2", tc.wantReason,
			} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q (target-name requirement, route position, id and 1-based rule index)",
						fail.Reason, want)
				}
			}
		})
	}
}
