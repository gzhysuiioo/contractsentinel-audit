// Offline route resolution: match a request against configured route prefixes
// and join the remainder onto the upstream base path without any network I/O.
package contractsentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// Route is one configured route: an id, accepted methods, a path prefix and
// the upstream URL requests on that route are forwarded to. An optional
// queryTransforms list rewrites the request query string after the route has
// been selected.
//
// QueryTransforms stays tag-less in the default (un)marshal sense: reading
// goes through Config.UnmarshalJSON via the routeJSON raw mirror, and writing
// goes through Route.MarshalJSON, so the rules round-trip instead of being
// silently dropped (a plain json:"-" tag only omitted them on save).
type Route struct {
	ID         string
	Methods    []string
	PathPrefix string
	Upstream   string

	// QueryTransforms holds the parsed rules. When it carries no rules the
	// field is omitted on save, whether the source named no field or an
	// explicit queryTransforms: [] — both are valid ways to write a route
	// without rules, and ParseConfig accepts either.
	QueryTransforms []*QueryTransform

	// queryTransformsRaw holds the undecoded queryTransforms value until
	// Config.UnmarshalJSON validates it once the route's position in its own
	// config is known. It is nil in every successfully parsed config.
	queryTransformsRaw json.RawMessage
}

// MarshalJSON writes routes back in the shape ParseConfig accepts: the four
// basic fields in their canonical order, followed by queryTransforms when the
// route carries rules. A route without rules — whether the source omitted the
// field or named queryTransforms: [] — omits it, and ParseConfig accepts
// either spelling; the field is never written as null. The rules' order and
// literal strings are preserved byte for byte apart from JSON string
// escaping, so re-parsing the output and resolving yields the same routeId
// and upstreamURL. Unexported fields never appear in the output.
func (r Route) MarshalJSON() ([]byte, error) {
	type routeOut struct {
		ID              string            `json:"id"`
		Methods         []string          `json:"methods"`
		PathPrefix      string            `json:"pathPrefix"`
		Upstream        string            `json:"upstream"`
		QueryTransforms []*QueryTransform `json:"queryTransforms,omitempty"`
	}
	return json.Marshal(routeOut{
		ID:              r.ID,
		Methods:         r.Methods,
		PathPrefix:      r.PathPrefix,
		Upstream:        r.Upstream,
		QueryTransforms: r.QueryTransforms,
	})
}

// QueryTransform is one rule in a route's queryTransforms array: op is
// "set", "remove" or "rename"; name is matched against decoded parameter
// names, value (set only) is used literally, and to (rename only) is the
// literal replacement name.
type QueryTransform struct {
	Op    string `json:"op"`
	Name  string `json:"name"`
	Value string `json:"value"`
	To    string `json:"to"`
}

// MarshalJSON renders each rule so the output satisfies the same constraints
// parseQueryTransforms enforces on input:
//   - set keeps "value" as a JSON string, including the empty string;
//   - remove emits only op and name (never value or to);
//   - rename keeps a non-empty "to" and never emits value.
//
// name, value and to are written as the literal strings read in — spaces,
// non-ASCII letters, '+' and '%' included — with only JSON string escaping,
// never query-string percent-encoding or decoding, so a re-read matches the
// same parameter names and applies the same literal values.
func (q *QueryTransform) MarshalJSON() ([]byte, error) {
	switch q.Op {
	case "set":
		return json.Marshal(struct {
			Op    string `json:"op"`
			Name  string `json:"name"`
			Value string `json:"value"`
		}{q.Op, q.Name, q.Value})
	case "rename":
		return json.Marshal(struct {
			Op   string `json:"op"`
			Name string `json:"name"`
			To   string `json:"to"`
		}{q.Op, q.Name, q.To})
	default:
		// remove (and any op a validated config could never carry) writes
		// neither value nor to, so the output cannot gain fields the reader
		// rejects.
		return json.Marshal(struct {
			Op   string `json:"op"`
			Name string `json:"name"`
		}{q.Op, q.Name})
	}
}

// routeJSON mirrors Route but keeps every field raw: the basic fields are
// type-checked in Config.UnmarshalJSON with the route's position (and, when
// available, its id), so a wrong field type is reported on that route rather
// than as a generic JSON decode error, and queryTransforms can surface
// null, wrong types and malformed rules the same way.
type routeJSON struct {
	ID              json.RawMessage `json:"id"`
	Methods         json.RawMessage `json:"methods"`
	PathPrefix      json.RawMessage `json:"pathPrefix"`
	Upstream        json.RawMessage `json:"upstream"`
	QueryTransforms json.RawMessage `json:"queryTransforms"`
}

// decodeRoute type-checks and decodes one raw route object. loc is the
// route's 1-based location in its config (e.g. "route 2"). The element's JSON
// type is checked first: a null entry or any non-object value fails on the
// entry itself, naming the position, the required object type and the type
// actually received, instead of falling through to a missing-field error such
// as a missing id. Field type errors then carry that location and, when the
// route supplies a valid non-empty string id anywhere in its object (even
// after the offending field), that id. Missing fields stay silent here and
// are rejected later by validate, which preserves the existing missing-field
// behavior.
func decodeRoute(data []byte, loc string) (Route, *Failure) {
	elem := bytes.TrimSpace(data)
	if len(elem) == 0 || elem[0] != '{' {
		return Route{}, failuref("invalid_config",
			"%s: route entry must be an object, got %s", loc, jsonTypeName(elem))
	}
	var rj routeJSON
	if err := json.Unmarshal(elem, &rj); err != nil {
		// The element already parsed as one JSON value and starts with '{';
		// an object that cannot be read is a syntax failure rather than a
		// field type error.
		return Route{}, failuref("invalid_config", "config is not valid JSON: %v", err)
	}

	var route Route
	// Type-check id first so it can identify the route on an error in any
	// later field regardless of object order. Only a valid non-empty JSON
	// string becomes the label; a wrong-typed id is reported against the id
	// field and never rendered (e.g. as a number or object) as the route's
	// identity, so that error is located by position alone.
	if !decodeStringField(rj.ID, &route.ID) {
		return Route{}, failuref("invalid_config", "%s: id must be a string", loc)
	}
	label := loc
	if route.ID != "" {
		label = routeLabel(loc, route.ID)
	}

	if f := decodeMethodsField(rj.Methods, label, &route.Methods); f != nil {
		return Route{}, f
	}
	if f := decodeRouteStringField(rj.PathPrefix, label, "pathPrefix", &route.PathPrefix); f != nil {
		return Route{}, f
	}
	if f := decodeRouteStringField(rj.Upstream, label, "upstream", &route.Upstream); f != nil {
		return Route{}, f
	}
	route.queryTransformsRaw = rj.QueryTransforms
	return route, nil
}

// decodeRouteStringField renders a route field's string type error with the
// route's position (and, when available, its id); the type decision itself is
// the shared decodeStringField. An absent field stays silent for the later
// required-field validation.
func decodeRouteStringField(raw json.RawMessage, label, field string, dst *string) *Failure {
	if !decodeStringField(raw, dst) {
		return failuref("invalid_config", "%s: %s must be a string", label, field)
	}
	return nil
}

// decodeStringField type-checks a raw field that must hold a string. It is
// the one shared string-field decision used by both config and request
// decoding, so the absent / null / non-string / empty-string distinctions
// live in one place. It returns false only when the key is present with a
// non-string value (null included), which is always a field type error. An
// absent key leaves dst untouched, and a present string — the empty string
// included — is decoded into dst, so both reach the existing content checks
// unchanged.
func decodeStringField(raw json.RawMessage, dst *string) (isString bool) {
	if len(raw) == 0 {
		return true
	}
	return jsonString(raw, dst)
}

// decodeMethodsField type-checks methods: it must be an array of strings
// when present. An absent field is left nil for later required-field
// validation; null or any non-array value fails the field, and a number,
// boolean, object or null entry fails with the offending entry's position.
func decodeMethodsField(raw json.RawMessage, label string, dst *[]string) *Failure {
	if len(raw) == 0 {
		return nil
	}
	body := bytes.TrimSpace(raw)
	if string(body) == "null" || len(body) == 0 || body[0] != '[' {
		return failuref("invalid_config", "%s: methods must be an array of strings", label)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(body, &elems); err != nil {
		return failuref("invalid_config", "%s: methods must be an array of strings", label)
	}
	methods := make([]string, 0, len(elems))
	for i, elem := range elems {
		var m string
		if !jsonString(bytes.TrimSpace(elem), &m) {
			return failuref("invalid_config", "%s: methods entry %d must be a string", label, i+1)
		}
		methods = append(methods, m)
	}
	*dst = methods
	return nil
}

// parseQueryTransforms decodes and validates the raw queryTransforms array
// of one route. loc identifies the route; rule errors additionally carry a
// 1-based rule index.
func parseQueryTransforms(raw json.RawMessage, loc, id string) ([]*QueryTransform, *Failure) {
	body := strings.TrimSpace(string(raw))
	if body == "null" {
		return nil, failuref("invalid_config", "%s: queryTransforms must not be null", routeLabel(loc, id))
	}
	var elems []json.RawMessage
	if err := json.Unmarshal([]byte(body), &elems); err != nil {
		return nil, failuref("invalid_config", "%s: queryTransforms must be an array", routeLabel(loc, id))
	}
	transforms := make([]*QueryTransform, 0, len(elems))
	for i, elem := range elems {
		ruleLoc := fmt.Sprintf("%s, queryTransforms rule %d", routeLabel(loc, id), i+1)
		if string(bytes.TrimSpace(elem)) == "null" {
			return nil, failuref("invalid_config", "%s: rule must not be null", ruleLoc)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(elem, &fields); err != nil {
			return nil, failuref("invalid_config", "%s: rule must be a JSON object", ruleLoc)
		}

		qt := &QueryTransform{}
		opRaw, ok := fields["op"]
		switch {
		case !ok:
			return nil, failuref("invalid_config", "%s: op is required", ruleLoc)
		case !jsonString(opRaw, &qt.Op):
			return nil, failuref("invalid_config", "%s: op must be a string", ruleLoc)
		case qt.Op != "set" && qt.Op != "remove" && qt.Op != "rename":
			return nil, failuref("invalid_config", "%s: unknown op %q (only set, remove and rename are supported)", ruleLoc, qt.Op)
		}

		nameRaw, ok := fields["name"]
		switch {
		case !ok:
			return nil, failuref("invalid_config", "%s: name is required", ruleLoc)
		case !jsonString(nameRaw, &qt.Name):
			return nil, failuref("invalid_config", "%s: name must be a non-empty string", ruleLoc)
		case qt.Name == "":
			return nil, failuref("invalid_config", "%s: name must be a non-empty string", ruleLoc)
		}

		valueRaw, hasValue := fields["value"]
		toRaw, hasTo := fields["to"]
		switch qt.Op {
		case "set":
			if !hasValue {
				return nil, failuref("invalid_config", "%s: set requires a string value", ruleLoc)
			}
			if !jsonString(valueRaw, &qt.Value) {
				return nil, failuref("invalid_config", "%s: value must be a string", ruleLoc)
			}
		case "remove":
			if hasValue {
				return nil, failuref("invalid_config", "%s: remove must not include a value", ruleLoc)
			}
		case "rename":
			if hasValue {
				return nil, failuref("invalid_config", "%s: rename must not include a value", ruleLoc)
			}
			switch {
			case !hasTo:
				return nil, failuref("invalid_config", "%s: rename requires a non-empty string to", ruleLoc)
			case !jsonString(toRaw, &qt.To):
				return nil, failuref("invalid_config", "%s: to must be a non-empty string", ruleLoc)
			case qt.To == "":
				return nil, failuref("invalid_config", "%s: to must be a non-empty string", ruleLoc)
			}
		}
		transforms = append(transforms, qt)
	}
	return transforms, nil
}

// jsonString decodes raw into s and reports whether raw is a JSON string
// (null, numbers, objects and arrays fail).
func jsonString(raw json.RawMessage, s *string) bool {
	if len(raw) == 0 || raw[0] != '"' {
		return false
	}
	return json.Unmarshal(raw, s) == nil
}

// routeLabel renders the human-readable route location, adding the id when
// the configuration supplied one.
func routeLabel(loc, id string) string {
	if id != "" {
		return fmt.Sprintf("%s (id %q)", loc, id)
	}
	return loc
}

// Config is the resolve configuration: a flat array of routes.
type Config struct {
	Routes []Route `json:"routes"`
}

// MarshalJSON writes the config back in the shape ParseConfig accepts. A
// non-nil empty (or nil) routes slice is emitted as "routes": [] rather than
// "routes": null, which ParseConfig would reject with invalid_config; the
// routes keep their parsed order and each route marshals through
// Route.MarshalJSON so its queryTransforms survive the save.
func (cfg *Config) MarshalJSON() ([]byte, error) {
	routes := cfg.Routes
	if routes == nil {
		routes = []Route{}
	}
	return json.Marshal(struct {
		Routes []Route `json:"routes"`
	}{Routes: routes})
}

// UnmarshalJSON first confirms the document is one syntactically valid JSON
// value, then checks its structure: the top-level value must be a JSON object
// and, when present, the routes field must hold an array. A syntactically
// legal value of the wrong shape (an array, string, number, boolean or null
// at the top level; a non-array routes, null included) is an invalid_config
// naming both the required type and the type received, never a JSON parse
// failure. The routes array is then decoded one entry at a time, each entry
// type-checked and validated against its 1-based position in this config; a
// non-object entry (null included) fails on that entry before any field is
// inspected. Decoding entries from raw values means wrong field types are
// reported on the offending route (with its id when available) instead of
// as a generic JSON syntax failure. The position comes from the array
// decoded here, so configs parsed concurrently or interleaved in the same
// process cannot shift each other's route numbering. A broken JSON document
// still fails the outer decode and is reported as a parse failure, without a
// guessed route position or field.
func (cfg *Config) UnmarshalJSON(data []byte) error {
	// Syntax first, then the top-level shape; both basic checks are shared
	// with ParseRequest (see unmarshalJSONValue / requireJSONObject), only
	// the code and wording differ.
	body, err := unmarshalJSONValue(data)
	if err != nil {
		return err
	}
	if f := requireJSONObject(body, "invalid_config", "config", true); f != nil {
		return f
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return err
	}

	var rawRoutes []json.RawMessage
	if raw, ok := fields["routes"]; ok {
		body := bytes.TrimSpace(raw)
		if len(body) == 0 || body[0] != '[' {
			// null is a type error here, never an absent field: a config
			// that explicitly supplies routes must supply an array.
			return failuref("invalid_config", "routes must be an array, got %s", jsonTypeName(body))
		}
		if err := json.Unmarshal(body, &rawRoutes); err != nil {
			return err
		}
	}

	// Pass 1: decode and type-check every entry, so a wrong field type on a
	// later route fails before any queryTransforms validation (matching the
	// precedence of decoding before validation).
	cfg.Routes = make([]Route, len(rawRoutes))
	for i, entry := range rawRoutes {
		route, f := decodeRoute(entry, fmt.Sprintf("route %d", i+1))
		if f != nil {
			return f
		}
		cfg.Routes[i] = route
	}
	// Pass 2: validate each route's queryTransforms now that every position
	// is known.
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		if len(route.queryTransformsRaw) == 0 {
			continue // field absent
		}
		loc := fmt.Sprintf("route %d", i+1)
		transforms, f := parseQueryTransforms(route.queryTransformsRaw, loc, route.ID)
		if f != nil {
			return f
		}
		route.QueryTransforms = transforms
		route.queryTransformsRaw = nil
	}
	return nil
}

// unmarshalJSONValue is the shared first step of parsing either input: it
// confirms the document is one syntactically valid JSON value, without
// judging its shape. It returns encoding/json's own error verbatim, so each
// caller keeps its existing handling (ParseConfig wraps a returned error just
// as Config.UnmarshalJSON returning it directly always has).
func unmarshalJSONValue(data []byte) (json.RawMessage, error) {
	var doc json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(doc), nil
}

// requireJSONObject is the shared top-level shape check: a syntactically
// legal value that is not a JSON object is a structural error in the caller's
// code saying "<what> must be a JSON object", never a parse failure and never
// a guessed field or route position. Config errors additionally name the type
// actually received ("got <type>"); the request wording omits it.
func requireJSONObject(doc json.RawMessage, code, what string, nameType bool) *Failure {
	if len(doc) == 0 || doc[0] != '{' {
		if nameType {
			return failuref(code, "%s must be a JSON object, got %s", what, jsonTypeName(doc))
		}
		return failuref(code, "%s must be a JSON object", what)
	}
	return nil
}

// Request is one resolution request: an HTTP method and a request target
// (path with an optional raw query string).
type Request struct {
	Method string `json:"method"`
	Target string `json:"target"`
}

// Resolution is the successful result of matching a request.
type Resolution struct {
	RouteID     string `json:"routeId"`
	UpstreamURL string `json:"upstreamURL"`
}

// Failure carries a stable machine-readable code and a human-readable reason.
type Failure struct {
	Code       string   `json:"code"`
	Reason     string   `json:"reason"`
	Candidates []string `json:"candidates,omitempty"`
}

func (f *Failure) Error() string { return f.Code + ": " + f.Reason }

func failuref(code, format string, args ...any) *Failure {
	return &Failure{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// ParseConfig parses and fully validates the route configuration.
func ParseConfig(data []byte) (*Config, *Failure) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		if f, ok := err.(*Failure); ok {
			return nil, f
		}
		return nil, failuref("invalid_config", "config is not valid JSON: %v", err)
	}
	if f := cfg.validate(); f != nil {
		return nil, f
	}
	return &cfg, nil
}

func (cfg *Config) validate() *Failure {
	seenIDs := make(map[string]int, len(cfg.Routes))
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		loc := fmt.Sprintf("route %d", i+1)
		if route.ID == "" {
			return failuref("invalid_config", "%s: id must be non-empty", loc)
		}
		if first, ok := seenIDs[route.ID]; ok {
			return failuref("invalid_config", "%s: duplicate id %q (already used by route %d)", loc, route.ID, first)
		}
		seenIDs[route.ID] = i + 1

		if len(route.Methods) == 0 {
			return failuref("invalid_config", "%s (id %q): methods must be a non-empty array", loc, route.ID)
		}
		for _, method := range route.Methods {
			switch {
			case method == "":
				return failuref("invalid_config", "%s (id %q): methods must not contain empty entries", loc, route.ID)
			case method == "*":
				// Wildcard matching any legal method.
			case !isToken(method):
				return failuref("invalid_config", "%s (id %q): invalid method %q", loc, route.ID, method)
			}
		}

		if f := validatePrefix(route.PathPrefix, loc, route.ID); f != nil {
			return f
		}
		if f := validateUpstream(route.Upstream, loc, route.ID); f != nil {
			return f
		}
	}
	return nil
}

func validatePrefix(prefix, loc, id string) *Failure {
	switch {
	case prefix == "" || prefix[0] != '/':
		return failuref("invalid_config", "%s (id %q): pathPrefix must start with /", loc, id)
	case prefix != "/" && strings.HasSuffix(prefix, "/"):
		return failuref("invalid_config", "%s (id %q): pathPrefix must not end with / except for root", loc, id)
	case strings.ContainsAny(prefix, "?#"):
		return failuref("invalid_config", "%s (id %q): pathPrefix must not contain a query string or fragment", loc, id)
	case !validPercentEscapes(prefix):
		return failuref("invalid_config", "%s (id %q): pathPrefix contains an invalid percent escape", loc, id)
	}
	return nil
}

func validateUpstream(raw, loc, id string) *Failure {
	if strings.ContainsAny(raw, "?#") {
		return failuref("invalid_config", "%s (id %q): upstream must not contain a query string or fragment", loc, id)
	}
	// Validate the host against the raw string before url.Parse: square
	// brackets are the IP-literal marker, so whatever they enclose must be a
	// legal IPv6 address (zone included) rather than a name or an IPv4
	// address, and a bare IPv6 literal is not allowed to omit them. Doing
	// this explicitly keeps both rules independent of url.Parse's parser
	// strictness and lets the reason name the field and the actual problem
	// instead of surfacing a generic URL parse error (a bare IPv6 literal
	// otherwise reads as a host carrying an invalid-looking ":port").
	if f := validateUnbracketedIPv6UpstreamHost(raw, loc, id); f != nil {
		return f
	}
	if f := validateBracketedUpstreamHost(raw, loc, id); f != nil {
		return f
	}
	u, err := url.Parse(raw)
	if err != nil {
		return failuref("invalid_config", "%s (id %q): upstream is not a valid URL: %v", loc, id, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return failuref("invalid_config", "%s (id %q): upstream must be an absolute http or https URL", loc, id)
	}
	if u.Host == "" {
		return failuref("invalid_config", "%s (id %q): upstream must include a host", loc, id)
	}
	return nil
}

// upstreamHostPort slices the authority's host (plus any port) out of the raw
// upstream on raw bytes: it starts after the scheme separator, ends at the
// first path slash (the caller has already rejected a query or fragment), and
// any userinfo ending at the last '@' is stripped. It returns ok=false when
// the raw URL has no scheme separator, in which case the generic
// absolute-URL check reports that and no host rule applies.
func upstreamHostPort(raw string) (hostPort string, ok bool) {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return "", false
	}
	authority := raw[schemeEnd+3:]
	if i := strings.IndexByte(authority, '/'); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	return authority, true
}

// validateUnbracketedIPv6UpstreamHost checks the raw upstream's host for an
// IPv6 literal written without its required square brackets:
//
//	http://2001:db8::1/base        -> invalid
//	http://[2001:db8::1]/base      -> valid
//
// RFC 3986 reserves brackets as the IP-literal marker precisely because an
// IPv6 address's colons would otherwise be indistinguishable from the
// host/port boundary, so the bare literal must be rejected rather than
// bracketed automatically or its last group guessed as a port. The rule
// covers full form (eight groups), compressed form ("::") and an IPv6
// address with an embedded IPv4 tail (e.g. "::ffff:192.0.2.1") — a literal
// that ends in a digit is still a bare literal, not a host with a port. A
// percent-encoded zone is part of the address, not a reason to skip the
// rule. Detection runs here on the raw bytes, before url.Parse, so the
// reason names the route, its id and the upstream field and says the IPv6
// host lacks brackets — a content error in valid JSON — instead of the
// parser's generic "invalid port after host" verdict, and independent of
// how strict the parser is about such authorities.
func validateUnbracketedIPv6UpstreamHost(raw, loc, id string) *Failure {
	hostPort, ok := upstreamHostPort(raw)
	if !ok {
		return nil // no scheme: the generic absolute-URL check reports this
	}
	// Brackets are validated separately. An ordinary reg-name (domain) or a
	// bare IPv4 host with a port carries exactly one colon ("example.com:8080",
	// "127.0.0.1:8080"), whereas a bare IPv6 literal always carries at least
	// two — seven in the full form, two adjacent ones ("::") in a compressed
	// form — so the colon count separates them without mistaking a port for
	// address bytes. Colons in the userinfo or base path never reach here
	// (both are sliced away), so they cannot make a legal host look bare.
	if strings.ContainsAny(hostPort, "[]") || strings.Count(hostPort, ":") < 2 {
		return nil
	}
	// The host bytes are parsed exactly as written, a percent-encoded zone
	// ("%25eth0") unescaped once so netip sees "fe80::1%eth0". A trailing
	// ":8080" is never split off as a guessed port: if the whole literal
	// parses as IPv6 (as "2001:db8::1:8080" or "::1:8080" do), it is a bare
	// IPv6 host that must have been bracketed.
	decoded, err := url.PathUnescape(hostPort)
	if err != nil {
		return invalidUnbracketedIPv6Host(loc, id, hostPort)
	}
	addr, err := netip.ParseAddr(decoded)
	if err != nil || !addr.Is6() {
		return nil // not an IPv6 literal; the generic URL checks judge it
	}
	return invalidUnbracketedIPv6Host(loc, id, hostPort)
}

// invalidUnbracketedIPv6Host builds the content error for a bare IPv6 host
// that omits its required square brackets.
func invalidUnbracketedIPv6Host(loc, id, hostPort string) *Failure {
	return failuref("invalid_config",
		"%s: upstream IPv6 host %q must be enclosed in square brackets, write it as \"[<ipv6>]\" (optionally followed by a port)",
		routeLabel(loc, id), hostPort)
}

// validateBracketedUpstreamHost checks the raw upstream's authority for an
// IP literal in square brackets: brackets are reserved for an IPv6 (or
// future IP-version) literal, so their content must parse as an IPv6 address
// — full form, compressed form or an IPv6 address with an embedded IPv4
// tail — and the brackets must wrap the whole host exactly once:
//
//	"[" IPv6 "]" [ ":" *DIGIT ]
//
// A port, userinfo and a percent-encoded zone ("%25eth0") are allowed and
// never alter the literal's bytes; an empty pair of brackets, a plain
// hostname such as "[not-an-ip]", a bare IPv4 address such as
// "[127.0.0.1]", a malformed IPv6 literal, a missing closing bracket, a
// second bracket group such as "[::1][::2]", a stray closing bracket or any
// other text between the closing bracket and the start of the base path
// (including junk around the port such as "[::1]:80a" or "[::1]x]:80") are
// rejected — a legal first literal never legitimizes trailing content. The
// reason names the route, its id and the upstream field. This is a content
// error in a syntactically valid JSON document, never a JSON parse failure,
// and the rule is enforced here on the raw bytes rather than left to
// url.Parse's parser strictness.
func validateBracketedUpstreamHost(raw, loc, id string) *Failure {
	hostPort, ok := upstreamHostPort(raw)
	if !ok {
		return nil // no scheme: the generic absolute-URL check reports this
	}

	if !strings.ContainsAny(hostPort, "[]") {
		return nil // ordinary reg-name (domain) or bare IPv4 host stays as-is
	}
	label := routeLabel(loc, id)
	if !strings.HasPrefix(hostPort, "[") {
		return failuref("invalid_config",
			"%s: upstream bracketed host must be a single '[' IPv6 address ']' pair: '[' may only open the host", label)
	}
	closeBracket := strings.IndexByte(hostPort, ']')
	if closeBracket < 0 {
		return failuref("invalid_config",
			"%s: upstream bracketed host must be a valid IPv6 address but the closing ']' is missing", label)
	}
	literal := hostPort[1:closeBracket]
	// The zone delimiter is percent-encoded in the URL ("%25"); decode the
	// literal's escapes once so netip sees "fe80::1%eth0" while every other
	// byte keeps its original spelling.
	decoded, err := url.PathUnescape(literal)
	if err != nil {
		return invalidBracketedHost(label, literal)
	}
	addr, err := netip.ParseAddr(decoded)
	if err != nil || !addr.Is6() {
		// ParseAddr accepts a bare IPv4 address; brackets may only carry
		// IPv6, so "[127.0.0.1]" is rejected even though it is a valid IP.
		return invalidBracketedHost(label, literal)
	}
	// The one closing bracket ends the host: the rest of the authority may
	// be empty or the optional port the generic parser already allows
	// (":" followed by digits, an empty port included). A repeated bracket
	// group, a stray ']', or any other text before, beside or after a port
	// fails here even though the first literal was valid — the brackets
	// must enclose the whole host exactly once.
	suffix := hostPort[closeBracket+1:]
	switch {
	case suffix == "":
		return nil
	case strings.ContainsAny(suffix, "[]"):
		return invalidBracketedHostShape(label, suffix)
	case suffix[0] != ':':
		return invalidBracketedHostShape(label, suffix)
	}
	port := suffix[1:]
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return invalidBracketedHostShape(label, suffix)
		}
	}
	return nil
}

// invalidBracketedHost builds the content error for a bracketed host whose
// content is not a legal IPv6 literal.
func invalidBracketedHost(label, literal string) *Failure {
	return failuref("invalid_config",
		"%s: upstream host in brackets must be a valid IPv6 address, but %q is not a legal IPv6 address", label, literal)
}

// invalidBracketedHostShape builds the content error for a bracketed host
// whose trailing bytes break the "single '[' IPv6 ']' pair plus optional
// port" grammar, e.g. a repeated bracket group, a stray closing bracket or
// non-port text after the closing bracket.
func invalidBracketedHostShape(label, suffix string) *Failure {
	return failuref("invalid_config",
		"%s: upstream bracketed host must be a single '[' IPv6 address ']' pair followed only by an optional port, but %q follows the closing ']'", label, suffix)
}

// requestJSON mirrors Request but keeps method and target raw, so a valid
// JSON document whose fields merely have the wrong JSON type is reported on
// the offending field instead of as a generic JSON decode error.
type requestJSON struct {
	Method json.RawMessage `json:"method"`
	Target json.RawMessage `json:"target"`
}

// ParseRequest parses and validates one JSON request. Three failure shapes are
// kept apart: a document whose JSON syntax is broken fails as a parse failure
// without guessing a field; a syntactically valid non-object document (array,
// number, string, boolean or null) must be a JSON object; a valid object whose
// method or target is not a string fails on that field, naming the JSON type
// actually received (null counts as a type error, never as a missing field).
// method is always checked before target, regardless of the key order in the
// object. Only after both fields are present strings are their contents
// (required method, legal token, absolute target without a fragment or a bad
// percent escape) validated, so an empty string stays a content error.
func ParseRequest(data []byte) (*Request, *Failure) {
	body, err := unmarshalJSONValue(data)
	if err != nil {
		return nil, failuref("invalid_request", "request is not valid JSON: %v", err)
	}
	if f := requireJSONObject(body, "invalid_request", "request", false); f != nil {
		return nil, f
	}

	var rj requestJSON
	if err := json.Unmarshal(body, &rj); err != nil {
		// The document already parsed as one JSON value and starts with '{';
		// keep this as a parse failure rather than a field error if the object
		// itself cannot be read.
		return nil, failuref("invalid_request", "request is not valid JSON: %v", err)
	}

	var req Request
	// method is always checked before target, regardless of the key order in
	// the object; the absent/null/non-string distinction is the shared
	// decodeStringField, so only the request wording is added here.
	if f := decodeRequestStringField(rj.Method, "method", &req.Method); f != nil {
		return nil, f
	}
	if f := decodeRequestStringField(rj.Target, "target", &req.Target); f != nil {
		return nil, f
	}

	switch {
	case req.Method == "":
		return nil, failuref("invalid_request", "method is required")
	case !isToken(req.Method):
		return nil, failuref("invalid_request", "method %q is not a legal HTTP method", req.Method)
	}
	switch {
	case req.Target == "" || req.Target[0] != '/':
		return nil, failuref("invalid_request", "target must start with /")
	case strings.Contains(req.Target, "#"):
		return nil, failuref("invalid_request", "target must not contain a fragment")
	case !validPercentEscapes(req.Target):
		return nil, failuref("invalid_request", "target contains an invalid percent escape")
	}
	return &req, nil
}

// decodeRequestStringField renders the request wording for one string field;
// the absent/null/non-string decision itself is the shared
// decodeStringField. An absent field (no such key) is left as the zero value
// so the later content checks keep their "field is required" behavior; null
// or any non-string JSON value is a type error that names the field and the
// JSON type that was actually supplied.
func decodeRequestStringField(raw json.RawMessage, field string, dst *string) *Failure {
	if !decodeStringField(raw, dst) {
		return failuref("invalid_request", "%s must be a string, got %s", field, jsonTypeName(raw))
	}
	return nil
}

// jsonTypeName names the JSON type of a syntactically valid raw value, in the
// terms the request error reasons use: "null", "a boolean", "a number",
// "a string", "an array" or "an object".
func jsonTypeName(raw json.RawMessage) string {
	switch bytes.TrimSpace(raw)[0] {
	case 'n':
		return "null"
	case 't', 'f':
		return "a boolean"
	case '"':
		return "a string"
	case '[':
		return "an array"
	case '{':
		return "an object"
	default:
		return "a number"
	}
}

// Resolve matches a validated request against a validated configuration and
// computes the upstream URL. Failure codes are route_not_found and
// route_conflict.
func Resolve(cfg *Config, req *Request) (*Resolution, *Failure) {
	path := req.Target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	type candidate struct {
		route    *Route
		concrete bool
	}
	var matched []candidate
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		concrete, wildcard := methodMatch(route.Methods, req.Method)
		if !concrete && !wildcard {
			continue
		}
		if !prefixMatch(route.PathPrefix, path) {
			continue
		}
		matched = append(matched, candidate{route, concrete})
	}
	if len(matched) == 0 {
		return nil, failuref("route_not_found", "no route matches %s %s", req.Method, path)
	}

	// Longest prefix wins.
	bestLen := 0
	for _, c := range matched {
		if n := len(c.route.PathPrefix); n > bestLen {
			bestLen = n
		}
	}
	winners := matched[:0]
	for _, c := range matched {
		if len(c.route.PathPrefix) == bestLen {
			winners = append(winners, c)
		}
	}

	// Among equal prefixes a concrete method beats the wildcard.
	var concrete []candidate
	for _, c := range winners {
		if c.concrete {
			concrete = append(concrete, c)
		}
	}
	if len(concrete) > 0 {
		winners = concrete
	}
	if len(winners) > 1 {
		ids := make([]string, 0, len(winners))
		for _, c := range winners {
			ids = append(ids, c.route.ID)
		}
		sort.Strings(ids)
		f := failuref("route_conflict", "multiple routes match %s %s", req.Method, path)
		f.Candidates = ids
		return nil, f
	}

	upstreamURL, f := joinUpstream(winners[0].route, path, req.Target)
	if f != nil {
		return nil, f
	}
	return &Resolution{RouteID: winners[0].route.ID, UpstreamURL: upstreamURL}, nil
}

// methodMatch reports whether the method list matches the request method
// concretely (an exact, case-sensitive entry) or via the "*" wildcard.
func methodMatch(methods []string, method string) (concrete, wildcard bool) {
	for _, m := range methods {
		switch {
		case m == "*":
			wildcard = true
		case m == method:
			concrete = true
		}
	}
	return concrete, wildcard
}

// prefixMatch matches raw encoded paths on segment boundaries: "%2F" is never
// treated as a separator and the root prefix matches every origin-path.
func prefixMatch(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix) && path[len(prefix)] == '/'
}

// joinUpstream strips the route prefix from the request path and joins the
// remainder onto the upstream base path with exactly one slash at the
// junction. The junction is one run of literal slashes: every trailing
// slash on the base path and every leading slash on the remainder are
// merged into that single slash, even when either side contributes
// several. Nothing else is normalized: slashes inside either part, the
// remainder's trailing slashes (once non-slash content has appeared),
// ".", ".." and percent escapes such as "%2F" are carried over byte for
// byte, never decoded first. The base path is sliced out of the raw
// upstream so joining never re-encodes, reorders or drops anything
// outside the junction. The raw query is preserved verbatim unless the
// route defines queryTransforms, in which case they rewrite it after
// route selection.
func joinUpstream(route *Route, path, target string) (string, *Failure) {
	if _, err := url.Parse(route.Upstream); err != nil {
		// Config validation already rejected this.
		return "", failuref("invalid_config", "route %q has an invalid upstream: %v", route.ID, err)
	}

	var remainder string
	switch {
	case route.PathPrefix == "/":
		// Root keeps the whole following path; "/" itself has an empty remainder.
		if path != "/" {
			remainder = path
		}
	default:
		remainder = path[len(route.PathPrefix):] // "" or "/...", boundary is a literal slash
	}

	// Slice the validated upstream raw so nothing outside the junction is
	// normalized or re-escaped (scheme://[userinfo@]host[/base-path]).
	schemeEnd := strings.Index(route.Upstream, "://")
	tail := route.Upstream[schemeEnd+3:]
	hostPart, basePath := tail, ""
	if i := strings.IndexByte(tail, '/'); i >= 0 {
		hostPart, basePath = tail[:i], tail[i:]
	}

	// Collapse only the junction run: all trailing slashes of the base
	// path meet all leading slashes of the remainder, and the junction
	// keeps exactly one slash whether or not anything follows them. A
	// remainder made entirely of slashes has no content past the run, so
	// it likewise ends in that single slash.
	baseTrimmed := strings.TrimRight(basePath, "/")
	rest := strings.TrimLeft(remainder, "/")
	joined := baseTrimmed + "/" + rest

	result := route.Upstream[:schemeEnd+3] + hostPart + joined
	query, f := applyQueryTransforms(route.QueryTransforms, target)
	if f != nil {
		return "", f
	}
	return result + query, nil
}

// isToken reports whether s is an RFC 7230 token, i.e. a legal HTTP method.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// validPercentEscapes checks that every "%' is followed by two hex digits.
// Matching and joining stay on raw strings, but malformed escapes are rejected
// up front for both prefixes and request targets.
func validPercentEscapes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

func isHex(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		return true
	}
	return false
}
