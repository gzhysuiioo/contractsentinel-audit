// Command saveconfig demonstrates the offline save path of the resolve
// configuration: read a config through the fully validating entry point,
// save it back to JSON, read the saved document again, and resolve the same
// request before and after the save. It runs entirely offline and only uses
// the library's public entry points.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// configJSON carries a query-rewrite chain: rename every "old" parameter to
// "new", then set the (now merged) "new" parameter to the empty string.
const configJSON = `{
  "routes": [
    {
      "id": "api",
      "methods": ["GET"],
      "pathPrefix": "/api",
      "upstream": "http://api.internal/v1",
      "queryTransforms": [
        {"op": "rename", "name": "old", "to": "new"},
        {"op": "set", "name": "new", "value": ""}
      ]
    }
  ]
}`

// requestJSON carries duplicate parameters, an empty value, a raw percent
// escape and a parameter without '='.
const requestJSON = `{"method":"GET","target":"/api/orders/7?old=1&old=&keep=%2f%41&flag"}`

func main() {
	// 1. Read the configuration through the fully validating entry point.
	//    ParseConfig runs every check layer; when it returns a Failure there
	//    is no usable config at all, and the document must not be used.
	cfg, f := contractsentinel.ParseConfig([]byte(configJSON))
	if f != nil {
		fatal(f)
	}

	// 2. Save the validated config as JSON. encoding/json drives the
	//    library's MarshalJSON methods, so routes, methods, prefixes,
	//    upstreams and the rewrite rules (order and literal strings) are
	//    preserved; indentation and JSON string escaping may differ from
	//    the original file.
	saved, err := json.Marshal(cfg)
	if err != nil {
		fatal(&contractsentinel.Failure{Code: "internal_error", Reason: err.Error()})
	}
	fmt.Printf("saved config: %s\n", saved)

	// 3. Re-read the saved document through the same entry point. A
	//    successful save is not proof the document is a legal config — only
	//    ParseConfig decides that — so the re-read is validated again, and a
	//    failure here stops the saved config from being used.
	reloaded, f := contractsentinel.ParseConfig(saved)
	if f != nil {
		fatal(f)
	}

	// 4. Resolve the same request against the config from before and after
	//    the save. Both sides must select the same route and produce the
	//    same upstreamURL.
	req, f := contractsentinel.ParseRequest([]byte(requestJSON))
	if f != nil {
		fatal(f)
	}
	for _, step := range []struct {
		label string
		cfg   *contractsentinel.Config
	}{
		{"before save", cfg},
		{"after save ", reloaded},
	} {
		res, f := contractsentinel.Resolve(step.cfg, req)
		if f != nil {
			fatal(f)
		}
		fmt.Printf("%s: routeId=%s upstreamURL=%s\n", step.label, res.RouteID, res.UpstreamURL)
	}

	// 5. An empty route list saves as "routes": [] (never null, which the
	//    reader rejects as a type error), re-reads as a legal config and
	//    answers every legal request with route_not_found.
	empty, f := contractsentinel.ParseConfig([]byte(`{"routes": []}`))
	if f != nil {
		fatal(f)
	}
	savedEmpty, err := json.Marshal(empty)
	if err != nil {
		fatal(&contractsentinel.Failure{Code: "internal_error", Reason: err.Error()})
	}
	fmt.Printf("saved empty config: %s\n", savedEmpty)
	reloadedEmpty, f := contractsentinel.ParseConfig(savedEmpty)
	if f != nil {
		fatal(f)
	}
	if _, f := contractsentinel.Resolve(reloadedEmpty, req); f != nil {
		fmt.Printf("empty config resolve: code=%s reason=%s\n", f.Code, f.Reason)
	}
}

// fatal reports a failure the way the resolve command does — the stable
// code and the human-readable reason — and stops; a config or request that
// failed to read is never used.
func fatal(f *contractsentinel.Failure) {
	fmt.Fprintf(os.Stderr, "code=%s reason=%s\n", f.Code, f.Reason)
	os.Exit(1)
}
