package main

import (
	"bytes"
	"strings"
	"testing"
)

// These tests pin the queryTransforms "copy" rule at the boundary a user
// actually uses: the copy rule is read from the config file, one JSON request
// arrives on stdin, and routeId plus upstreamURL show the copied query. They
// never open a network connection and do not need the upstreams to exist, so
// they reproduce deterministically offline.

// TestResolveCLICopyQueryTransform drives the headline copy behavior end to
// end. Copying "old" to "new" keeps every same-named source where it is and
// inserts each copy right after its source; the pre-existing new=9 stays in
// place (no merge, no overwrite); sources match by decoded name ("%6Fld")
// while their raw name spelling is left untouched; an empty value keeps its
// '=' and a parameter without '=' stays valueless in the copy. The success
// contract is the whole command's: exit 0, exactly one result JSON on stdout,
// empty stderr and raw '&' in upstreamURL (never a & escape).
func TestResolveCLICopyQueryTransform(t *testing.T) {
	config := `{
	  "routes": [
	    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
	     "upstream": "http://orders.internal",
	     "queryTransforms": [{"op": "copy", "name": "old", "to": "new"}]}
	  ]
	}`
	request := `{"method":"GET","target":"/api/orders/7?old=%2f+&new=9&%6Fld=&old"}`

	res := runResolveCLI(t, config, request)
	success := assertResolveSuccess(t, res)
	if success.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", success.RouteID)
	}
	wantURL := "http://orders.internal/7?old=%2f+&new=%2f+&new=9&%6Fld=&new=&old&new"
	if success.UpstreamURL != wantURL {
		t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
	// The copied query carries raw '&' separators, emitted literally rather
	// than as a JSON unicode escape, and stdout is just the one result object.
	if !bytes.Contains(res.stdout, []byte("&")) {
		t.Errorf("stdout should contain raw '&': %s", res.stdout)
	}
	if bytes.Contains(res.stdout, []byte("\\u0026")) {
		t.Errorf("stdout must not unicode-escape '&': %s", res.stdout)
	}
}

// TestResolveCLICopyBytesAndOrder covers the byte-level rules at the boundary:
// values (percent-escape case, '+', extra '=') are copied byte for byte, the
// empty-value and valueless forms stay distinct, sources match by decoded
// name without being re-encoded, unrelated parameters and empty fragments keep
// their bytes and order, no query string is created and an empty question mark
// survives, and copying a name onto itself neither duplicates nor re-encodes.
func TestResolveCLICopyBytesAndOrder(t *testing.T) {
	rootCopyConfig := func(rule string) string {
		return `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
			`"upstream":"http://h.internal/base","queryTransforms":[` + rule + `]}]}`
	}
	copyOldToNew := `{"op":"copy","name":"old","to":"new"}`
	cases := []struct {
		name    string
		rule    string
		target  string
		wantURL string
	}{
		{
			name:    "value bytes are copied verbatim including escape case plus and extra equals",
			rule:    copyOldToNew,
			target:  "/p?old=%2f+%2F+a=b&x",
			wantURL: "http://h.internal/base/p?old=%2f+%2F+a=b&new=%2f+%2F+a=b&x",
		},
		{
			name:    "empty value keeps equals while a valueless parameter stays valueless",
			rule:    copyOldToNew,
			target:  "/p?old=&new=9&old",
			wantURL: "http://h.internal/base/p?old=&new=&new=9&old&new",
		},
		{
			name:    "source matches by decoded name but keeps its raw percent encoded spelling",
			rule:    copyOldToNew,
			target:  "/p?%6Fld=1&keep=2",
			wantURL: "http://h.internal/base/p?%6Fld=1&new=1&keep=2",
		},
		{
			name:    "unrelated parameters and empty fragments keep content and order",
			rule:    copyOldToNew,
			target:  "/p?a=1&&old=2&&",
			wantURL: "http://h.internal/base/p?a=1&&old=2&new=2&&",
		},
		{
			name:    "no query string is created by a copy",
			rule:    copyOldToNew,
			target:  "/p",
			wantURL: "http://h.internal/base/p",
		},
		{
			name:    "empty question mark survives a copy that has no source",
			rule:    copyOldToNew,
			target:  "/p?",
			wantURL: "http://h.internal/base/p?",
		},
		{
			name:    "copy onto the same name neither duplicates nor re encodes",
			rule:    `{"op":"copy","name":"a b","to":"a b"}`,
			target:  "/p?a+b=1&a%20b=2",
			wantURL: "http://h.internal/base/p?a+b=1&a%20b=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := `{"method":"GET","target":"` + tc.target + `"}`
			success := assertResolveSuccess(t, runResolveCLI(t, rootCopyConfig(tc.rule), request))
			if success.RouteID != "root" {
				t.Errorf("routeId = %q, want root", success.RouteID)
			}
			if success.UpstreamURL != tc.wantURL {
				t.Errorf("upstreamURL = %q, want %q", success.UpstreamURL, tc.wantURL)
			}
		})
	}
}

// TestResolveCLICopyThenRemoveKeepsCopies pins rule order the way a user
// observes it: a copy followed by a remove of the source name deletes only the
// source parameters (including a percent-encoded spelling of the same decoded
// name), while every copy and the pre-existing target parameter survive in
// their existing relative order.
func TestResolveCLICopyThenRemoveKeepsCopies(t *testing.T) {
	config := `{"routes":[{"id":"root","methods":["*"],"pathPrefix":"/",` +
		`"upstream":"http://h.internal/base","queryTransforms":[
		  {"op":"copy","name":"old","to":"new"},
		  {"op":"remove","name":"old"}
		]}]}`
	request := `{"method":"GET","target":"/p?old=1&new=9&%6Fld=&old&keep=x"}`

	success := assertResolveSuccess(t, runResolveCLI(t, config, request))
	if success.RouteID != "root" {
		t.Errorf("routeId = %q, want root", success.RouteID)
	}
	wantURL := "http://h.internal/base/p?new=1&new=9&new=&new&keep=x"
	if success.UpstreamURL != wantURL {
		t.Fatalf("upstreamURL = %q, want %q", success.UpstreamURL, wantURL)
	}
	// No source spelling (raw or percent-encoded) remains.
	for _, leftover := range []string{"old", "%6Fld"} {
		if strings.Contains(success.UpstreamURL, leftover) {
			t.Errorf("upstreamURL = %q must not keep source %q after remove", success.UpstreamURL, leftover)
		}
	}
}

// copyTwoRoutesConfig gives a wide wildcard and a longer concrete route that
// both match /api requests, each with a different copy, so a resolved query
// shows which route's copy actually ran.
const copyTwoRoutesConfig = `{
  "routes": [
    {"id": "wide", "methods": ["*"], "pathPrefix": "/api",
     "upstream": "http://wide.internal/w",
     "queryTransforms": [{"op": "copy", "name": "old", "to": "widecopy"}]},
    {"id": "orders", "methods": ["GET"], "pathPrefix": "/api/orders",
     "upstream": "http://orders.internal",
     "queryTransforms": [{"op": "copy", "name": "old", "to": "new"}]}
  ]
}`

// TestResolveCLICopyOnlyOnSelectedRoute proves a copy belongs to the finally
// matched route: it neither changes prefix selection nor the upstream base
// path join, and a losing route's copy never executes. The empty-remainder
// case still keeps the single junction slash.
func TestResolveCLICopyOnlyOnSelectedRoute(t *testing.T) {
	// GET /api/orders/7 selects the longer concrete route; the wildcard
	// route's old->widecopy must not touch the query, and the /7 join onto a
	// host-only upstream is unchanged.
	longer := assertResolveSuccess(t, runResolveCLI(t, copyTwoRoutesConfig,
		`{"method":"GET","target":"/api/orders/7?old=1&new=9&old"}`))
	if longer.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders (longest prefix wins)", longer.RouteID)
	}
	if want := "http://orders.internal/7?old=1&new=1&new=9&old&new"; longer.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", longer.UpstreamURL, want)
	}
	if strings.Contains(longer.UpstreamURL, "widecopy") {
		t.Errorf("the losing route's copy must not run: %q", longer.UpstreamURL)
	}

	// Prefix equal to the request path leaves an empty remainder; the junction
	// slash onto the host-only upstream is preserved alongside the copies.
	empty := assertResolveSuccess(t, runResolveCLI(t, copyTwoRoutesConfig,
		`{"method":"GET","target":"/api/orders?old=1"}`))
	if empty.RouteID != "orders" {
		t.Errorf("routeId = %q, want orders", empty.RouteID)
	}
	if want := "http://orders.internal/?old=1&new=1"; empty.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", empty.UpstreamURL, want)
	}

	// A request only the wide route matches runs that route's own copy and
	// joins onto its base path normally.
	wide := assertResolveSuccess(t, runResolveCLI(t, copyTwoRoutesConfig,
		`{"method":"POST","target":"/api/x?old=1"}`))
	if wide.RouteID != "wide" {
		t.Errorf("routeId = %q, want wide", wide.RouteID)
	}
	if want := "http://wide.internal/w/x?old=1&widecopy=1"; wide.UpstreamURL != want {
		t.Errorf("upstreamURL = %q, want %q", wide.UpstreamURL, want)
	}
}

// TestResolveCLICopyInvalidToRejectsConfig drives the copy config contract at
// the command boundary: a missing or empty "to" (and likewise a non-string
// "to" or a forbidden "value") invalidates the whole configuration even
// though the offending route can never match this request. Failure leaves
// stdout completely empty and puts one JSON invalid_config error on stderr
// whose reason states the target-name requirement and names the 1-based route
// position, the route id and the 1-based rule index.
func TestResolveCLICopyInvalidToRejectsConfig(t *testing.T) {
	cases := []struct {
		name string
		bad  string
		want string
	}{
		{"to missing", `{"op":"copy","name":"old"}`, "copy requires a non-empty string to"},
		{"to empty", `{"op":"copy","name":"old","to":""}`, "to must be a non-empty string"},
		{"to numeric", `{"op":"copy","name":"old","to":7}`, "to must be a non-empty string"},
		{"to null", `{"op":"copy","name":"old","to":null}`, "to must be a non-empty string"},
		{"value forbidden", `{"op":"copy","name":"old","to":"new","value":"x"}`, "copy must not include a value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Route 1 ("hit") serves every request via the root prefix; route
			// 2 ("admin") never matches. A valid set rule precedes the bad
			// copy, pinning the reported location to rule 2.
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
				t.Fatalf("code = %q, want invalid_config", fail.Code)
			}
			for _, want := range []string{"route 2", `"admin"`, "rule 2", tc.want} {
				if !strings.Contains(fail.Reason, want) {
					t.Errorf("reason = %q, want substring %q (route position, id, 1-based rule index and target-name requirement)",
						fail.Reason, want)
				}
			}
			if strings.Contains(fail.Reason, "not valid JSON") {
				t.Errorf("a bad copy rule is a content error, not a JSON syntax failure: %q", fail.Reason)
			}
		})
	}
}
