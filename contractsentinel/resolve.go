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
// A Route only ever holds validated data: reading goes through
// Config.UnmarshalJSON, which decodes into the intermediate decodedRoute and
// copies a route out only once every check it owns has passed, and writing
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

// decodedRoute is the intermediate parse-stage representation of one route:
// the partially checked formal Route plus the queryTransforms value still
// awaiting validation. It exists only inside config decoding, so the
// temporary raw text never lives on the formal Route a successfully parsed
// Config hands out: decodeRoutes validates the raw value into
// route.QueryTransforms before any Route leaves the decode stage, and a
// rejected document yields no routes at all.
type decodedRoute struct {
	route Route
	// queryTransformsRaw holds the undecoded queryTransforms value until the
	// rule pass validates it, once every route's basic fields have been
	// type-checked (see decodeRoutes for why the passes are ordered so).
	queryTransformsRaw json.RawMessage
}

// decodeRoute type-checks and decodes one raw route object into the
// intermediate decodedRoute. loc is the route's 1-based location in its
// config (e.g. "route 2"). The element's JSON type is checked first: a null
// entry or any non-object value fails on the entry itself, naming the
// position, the required object type and the type actually received, instead
// of falling through to a missing-field error such as a missing id. Field
// type errors then carry that location and, when the route supplies a valid
// non-empty string id anywhere in its object (even after the offending
// field), that id. Missing fields stay silent here and are rejected later by
// validate, which preserves the existing missing-field behavior. The raw
// queryTransforms value is carried over unchecked: rule validation is the
// next decode pass, not this function's responsibility.
func decodeRoute(data []byte, loc string) (decodedRoute, *Failure) {
	elem := bytes.TrimSpace(data)
	if len(elem) == 0 || elem[0] != '{' {
		return decodedRoute{}, failuref("invalid_config",
			"%s: route entry must be an object, got %s", loc, jsonTypeName(elem))
	}
	var rj routeJSON
	if err := json.Unmarshal(elem, &rj); err != nil {
		// The element already parsed as one JSON value and starts with '{';
		// an object that cannot be read is a syntax failure rather than a
		// field type error.
		return decodedRoute{}, failuref("invalid_config", "config is not valid JSON: %v", err)
	}

	var decoded decodedRoute
	route := &decoded.route
	// Type-check id first so it can identify the route on an error in any
	// later field regardless of object order. Only a valid non-empty JSON
	// string becomes the label; a wrong-typed id is reported against the id
	// field and never rendered (e.g. as a number or object) as the route's
	// identity, so that error is located by position alone.
	if !decodeStringField(rj.ID, &route.ID) {
		return decodedRoute{}, failuref("invalid_config", "%s: id must be a string", loc)
	}
	label := loc
	if route.ID != "" {
		label = routeLabel(loc, route.ID)
	}

	if f := decodeMethodsField(rj.Methods, label, &route.Methods); f != nil {
		return decodedRoute{}, f
	}
	if f := decodeRouteStringField(rj.PathPrefix, label, "pathPrefix", &route.PathPrefix); f != nil {
		return decodedRoute{}, f
	}
	if f := decodeRouteStringField(rj.Upstream, label, "upstream", &route.Upstream); f != nil {
		return decodedRoute{}, f
	}
	decoded.queryTransformsRaw = rj.QueryTransforms
	return decoded, nil
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
// failure. The routes array is then handed to decodeRoutes, which decodes one
// entry at a time from raw values, so wrong field types are reported on the
// offending route (with its id when available) instead of as a generic JSON
// syntax failure, and each entry is checked against its 1-based position in
// this config — configs parsed concurrently or interleaved in the same
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

	routes, f := decodeRoutes(rawRoutes)
	if f != nil {
		return f
	}
	cfg.Routes = routes
	return nil
}

// decodeRoutes is the decode stage of config reading: it turns the raw routes
// array into fully checked formal Routes, owning every error layer that is
// decided during decoding. The layers run as two whole-array passes so a
// higher-priority error on a later route always beats a lower-priority one on
// an earlier route:
//
//   - Pass 1 (structure and basic field types): each entry is decoded by
//     decodeRoute, which rejects a non-object entry and any wrong-typed
//     id/methods/pathPrefix/upstream field. The raw queryTransforms value is
//     kept unchecked on the intermediate decodedRoute.
//   - Pass 2 (queryTransforms rules): only once every entry's basic fields
//     have the right JSON type are the rules decoded and validated by
//     parseQueryTransforms, so a rule error is reported only when no field
//     type error remains anywhere in the array.
//
// Within one pass the earliest array position wins: routes by their position
// in the routes array and rules by their position in the route's
// queryTransforms array, never by id ordering and regardless of the object
// field order. Field CONTENT errors (a non-absolute pathPrefix, a bad method
// token, an empty id, ...) are not this stage's concern: they are the
// validate stage's, which ParseConfig runs only after decoding has accepted
// every route, so any rule error still beats any content error. On the first
// failure decodeRoutes returns no routes at all, so no half-decoded
// configuration can escape the decode stage.
func decodeRoutes(rawRoutes []json.RawMessage) ([]Route, *Failure) {
	// Pass 1: decode and type-check every entry, so a wrong field type on a
	// later route fails before any queryTransforms validation (matching the
	// precedence of decoding before validation).
	decoded := make([]decodedRoute, len(rawRoutes))
	for i, entry := range rawRoutes {
		dr, f := decodeRoute(entry, fmt.Sprintf("route %d", i+1))
		if f != nil {
			return nil, f
		}
		decoded[i] = dr
	}
	// Pass 2: validate each route's queryTransforms now that every basic
	// field type is known to be right, then move the checked rules onto the
	// formal route.
	for i := range decoded {
		if len(decoded[i].queryTransformsRaw) == 0 {
			continue // field absent
		}
		loc := fmt.Sprintf("route %d", i+1)
		transforms, f := parseQueryTransforms(decoded[i].queryTransformsRaw, loc, decoded[i].route.ID)
		if f != nil {
			return nil, f
		}
		decoded[i].route.QueryTransforms = transforms
	}
	// Only fully checked routes leave the decode stage; the raw intermediate
	// form is dropped here.
	routes := make([]Route, len(decoded))
	for i := range decoded {
		routes[i] = decoded[i].route
	}
	return routes, nil
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

// ParseConfig parses and fully validates the route configuration. When one
// document carries several errors, the one reported is chosen by two stages
// running in a fixed order, each stage owning its layers:
//
//  1. decoding (Config.UnmarshalJSON): JSON syntax (a broken document is only
//     ever a parse failure, with no guessed route position or field), then
//     the top-level structure and the routes element and basic field types,
//     then the queryTransforms array and rule validity (see decodeRoutes);
//  2. validation (Config.validate): field contents — a non-empty unique id,
//     legal method tokens, an absolute pathPrefix and a well-formed upstream.
//
// A stage runs only when every earlier stage accepted the whole document, so
// a type error anywhere beats every rule error and a rule error anywhere
// beats every content error; within one layer the earliest array position
// wins (routes by routes-array order, rules by their queryTransforms order,
// never by id). Every failure hands back no config at all, so no half-parsed
// configuration can ever resolve a request.
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

// validate is the validation stage of config reading (see ParseConfig for
// how it layers with decoding): every route has already passed the decode
// stage's structure, type and rule checks, and this stage checks field
// contents in routes-array order — a non-empty unique id, legal method
// tokens, an absolute pathPrefix and a well-formed upstream.
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

// upstreamParts is the one shared reading of a raw upstream URL's address
// boundaries. Every field is a slice of the original bytes (nothing is
// copied, decoded or normalized), so validation and joining cannot disagree
// about where one part ends and the next begins:
//
//	scheme "://" [userinfo "@"] hostPort basePath
//
// authority runs from after "://" to the first path slash, and hostPort is
// the authority after its last '@', so colons in userinfo or the base path
// can never be read as part of an IPv6 host, while brackets, a port and a
// zone stay inside hostPort.
type upstreamParts struct {
	raw       string // the upstream exactly as configured; every other field slices this
	schemeEnd int    // index of the ':' in "://", or -1 when the scheme is absent
	authority string // bytes between "://" and the first path slash (userinfo included)
	hostPort  string // authority after the last '@' (host plus optional port)
	basePath  string // from the first path slash to the end, or ""
}

// splitUpstream applies the single boundary rule shared by the bracketed-host
// check, the unbracketed-IPv6 check and the final join. It never rejects
// anything on its own: a raw value without "://" comes back with schemeEnd
// set to -1 and empty parts, leaving the generic absolute-URL check to
// report it, exactly as the per-caller preamble used to.
func splitUpstream(raw string) upstreamParts {
	p := upstreamParts{raw: raw, schemeEnd: -1}
	i := strings.Index(raw, "://")
	if i < 0 {
		return p
	}
	p.schemeEnd = i
	tail := raw[i+3:]
	if j := strings.IndexByte(tail, '/'); j >= 0 {
		p.authority = tail[:j]
		p.basePath = tail[j:]
	} else {
		p.authority = tail
	}
	// Any userinfo precedes the host and ends at the last '@'; that boundary
	// is what keeps a userinfo colon out of the IPv6-host checks.
	p.hostPort = p.authority
	if k := strings.LastIndexByte(p.authority, '@'); k >= 0 {
		p.hostPort = p.authority[k+1:]
	}
	return p
}

func validateUpstream(raw, loc, id string) *Failure {
	if strings.ContainsAny(raw, "?#") {
		return failuref("invalid_config", "%s (id %q): upstream must not contain a query string or fragment", loc, id)
	}
	// Validate the host's IP-literal spelling against the raw string before
	// url.Parse: square brackets are the IP-literal marker, so whatever they
	// enclose must be a legal IPv6 address (full, compressed or IPv4-tail,
	// zone included) rather than a name or an IPv4 address, and an IPv6
	// literal may never appear without that pair of brackets. Both checks and
	// the later join read the same splitUpstream boundaries, which keeps the
	// rules independent of url.Parse's parser strictness and lets the reason
	// name the field and the actual problem instead of surfacing a generic URL
	// parse error (an unbracketed literal otherwise reaches the user as a
	// misleading "invalid port" complaint).
	p := splitUpstream(raw)
	if f := validateBracketedUpstreamHost(p, loc, id); f != nil {
		return f
	}
	if f := validateUnbracketedUpstreamHost(p, loc, id); f != nil {
		return f
	}
	if f := validateUpstreamHostPresent(p, loc, id); f != nil {
		return f
	}
	if f := validateUpstreamBasePathSpace(p, loc, id); f != nil {
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

// validateUpstreamHostPresent enforces on the split raw boundaries that the
// authority carries a non-empty host:
//
//	scheme "://" [userinfo "@"] host [":" port] [basePath]
//
// The check is needed because url.Parse treats a leading colon as a port
// separator with an empty hostname: it reads "http://:8080/base" with
// Host==":8080" and Hostname()=="" instead of rejecting it, so a check on
// u.Host alone lets the address through and the joined upstream is emitted
// without a host. The raw decision therefore fails every hostPort that is
// empty or begins with the port colon — an empty authority
// ("http:///base"), an authority reduced to userinfo ("http://u@/base"),
// a bare port with or without digits ("http://:8080/base",
// "https://:8443", "http://:/base") and any of those after userinfo
// ("https://user:p%40ss@:8443/v1"). Neither userinfo, the port nor a base
// path can fill the host slot, no default address is ever substituted, and
// a host that is simply followed by an empty port ("http://host:/base")
// stays accepted: its hostPort begins with the host, not the separator.
// Like the bracket rules this is a content error in a syntactically valid
// JSON document — the reason names the route's 1-based position, its id and
// the upstream field and says the upstream is missing a host, never that
// the JSON is broken or that an IPv6 literal needs brackets.
func validateUpstreamHostPresent(p upstreamParts, loc, id string) *Failure {
	if p.schemeEnd < 0 {
		return nil // no scheme: the generic absolute-URL check reports this
	}
	hostPort := p.hostPort
	if hostPort != "" && hostPort[0] != ':' {
		return nil
	}
	return failuref("invalid_config",
		"%s: upstream %q is missing a host: the address must carry a non-empty host before any port (e.g. \"http://example.com:8080/base\"); a port cannot serve as the host, and userinfo or a base path cannot fill the host in either; no default host is added",
		routeLabel(loc, id), p.raw)
}

// validateUpstreamBasePathSpace rejects a direct ASCII space (U+0020) in the
// upstream base path — inside a path segment, beside a slash or at the end,
// it is all the same error. Only percent encoding may carry a space there:
// "%20" is legal path content and is never decoded first, so an encoded
// space stays accepted while the literal byte is rejected. The check reads
// the same splitUpstream base-path boundaries the join uses, so a space that
// would reach upstreamURL can never pass validation. It is decided on the
// decoded configured string (a " " JSON escape decodes to the same
// byte), only the ASCII space is rejected — the rule is not widened to other
// Unicode whitespace — and the address is judged exactly as configured: the
// space is never stripped, the path never trimmed and the byte never
// re-encoded on the user's behalf. The reason names the route's 1-based
// position, its id and the upstream field; like the host rules this is a
// content error in a syntactically valid JSON document, never a JSON parse
// failure.
func validateUpstreamBasePathSpace(p upstreamParts, loc, id string) *Failure {
	if p.schemeEnd < 0 {
		return nil // no scheme: the generic absolute-URL check reports this
	}
	if !strings.ContainsRune(p.basePath, ' ') {
		return nil
	}
	return failuref("invalid_config",
		"%s: upstream base path contains an unencoded space (U+0020): a space in the upstream address must be percent-encoded as %%20 in the configuration; the address is used exactly as configured and the space is never stripped, the path never trimmed and the byte never encoded on its behalf",
		routeLabel(loc, id))
}

// validateBracketedUpstreamHost checks the split raw upstream's authority for
// an IP literal in square brackets: brackets are reserved for an IPv6 (or
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
func validateBracketedUpstreamHost(p upstreamParts, loc, id string) *Failure {
	if p.schemeEnd < 0 {
		return nil // no scheme: the generic absolute-URL check reports this
	}
	hostPort := p.hostPort

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

// validateUnbracketedUpstreamHost checks the split raw upstream's
// authority-without-brackets (hostPort) against the authority grammar:
//
//	host = IP-literal / IPv4address / reg-name
//	IP-literal = "[" ( IPv6address / ... ) "]"
//
// An unbracketed host part may therefore carry at most one colon, the one
// separating the host from its port:
//
//	reg-name [ ":" port ]
//
// Two or more colons are illegal no matter what the bytes spell: a bare IPv6
// literal leaves the host/port boundary undefined (the reader cannot tell
// "::1" from "::1:8080" with a port) and must be written as "[2001:db8::1]",
// while a name such as "api:internal:8080" or even a malformed IPv6-shaped
// spelling such as "2001:db8:::1" is not rescued by a numeric last segment —
// an extra colon stays an extra colon whether or not the address parses as
// IPv6 and whether or not a base path follows. The spelling is rejected on
// the colon count alone: the host and port are never guessed apart, brackets
// are never inserted and a trailing run of digits is never promoted to a
// port, so validity never depends on this Go release's url.Parse port
// strictness.
//
// When the part does parse as an IPv6 literal as written, the reason keeps
// the existing missing-brackets wording; a part that is merely
// multi-colon gets the extra-colon wording. The decision never strips a
// trailing ":<digits>" segment as a hypothetical port: every true bare IPv6
// spelling already parses whole ("::1:8080" and "fe80::1:8443" are complete
// addresses, whose last hextet merely happens to be digits), so stripping
// would only mislabel a malformed spelling such as "2001:db8:::1" that
// parses once a hextet is removed. Both reasons cover every form — the full
// form, the compressed form ("::1"), an IPv6 address with an embedded IPv4
// tail ("::ffff:192.0.2.1") and a percent-encoded zone ("%25eth0") — and
// both name the route's 1-based position, its id and the upstream field.
//
// Ordinary domains and bare IPv4 hosts (with or without a port) stay
// untouched, and the colons in userinfo or the base path are never
// inspected: only hostPort — the authority after the last '@' and before
// the first '/' according to the shared splitUpstream boundaries — is
// considered. Like the bracketed-host rule this is a content error in a
// syntactically valid JSON document, never a JSON parse failure, and it is
// decided on the raw bytes before url.Parse so the wording cannot regress to
// that parser's generic "invalid port" error.
func validateUnbracketedUpstreamHost(p upstreamParts, loc, id string) *Failure {
	if p.schemeEnd < 0 {
		return nil // no scheme: the generic absolute-URL check reports this
	}
	hostPort := p.hostPort
	if hostPort == "" || strings.ContainsAny(hostPort, "[]") {
		// No host (the generic check reports it) or a bracketed literal,
		// which the bracketed-host validator owns.
		return nil
	}

	// A single colon is the legal host/port separator ("host:8080"); zero
	// colons is a bare host. Count raw colons only: percent-encoded colons
	// ("%3A") carry no separator byte, and userinfo and the base path were
	// sliced off by splitUpstream.
	if strings.Count(hostPort, ":") <= 1 {
		return nil
	}
	label := routeLabel(loc, id)

	// Classify the spelling as written, never guessing a host/port split:
	// percent-decode once so a "%25eth0" zone reaches netip as "%eth0" while
	// every other byte keeps its spelling, then parse the whole hostPort. A
	// legal IPv6 literal keeps the existing missing-brackets reason (this
	// covers every form, "::1:8080" and "fe80::1:8443" included — a trailing
	// hextet of digits is part of the address, not a guessed port); anything
	// else that merely carries extra colons gets the extra-colon reason.
	decoded, err := url.PathUnescape(hostPort)
	if err == nil {
		if addr, perr := netip.ParseAddr(decoded); perr == nil && addr.Is6() {
			return failuref("invalid_config",
				"%s: upstream IPv6 host %q is missing its square brackets: an IPv6 literal must be enclosed in a pair of brackets with any port outside them (e.g. \"[2001:db8::1]:8080\"); brackets are never added and a trailing number is not guessed as a port",
				label, hostPort)
		}
	}
	return failuref("invalid_config",
		"%s: upstream %q has an unbracketed host part %q with more than one colon: a host without square brackets may contain at most the one colon separating it from its port (e.g. \"example.com:8080\"); an IPv6 literal must be enclosed in brackets (e.g. \"[2001:db8::1]:8080\") and the host and port are never guessed apart",
		label, p.raw, hostPort)
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
// (required method, legal token, absolute target without a fragment, a bad
// percent escape, or a direct space/control character) validated, so an empty
// string stays a content error.
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
	if f := validateTargetCharacters(req.Target); f != nil {
		return nil, f
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
	// Reject a target carrying a direct space or control character before
	// route selection, conflict resolution and query rewriting, so such a
	// request can never match a prefix (and carry the byte into
	// upstreamURL), report a conflict, or have a remove/set hide the
	// offending parameter. ParseRequest already ran this check; it is
	// repeated here so a request built in-process cannot bypass it.
	if f := validateTargetCharacters(req.Target); f != nil {
		return nil, f
	}
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
	// normalized or re-escaped. The address boundaries come from the same
	// splitUpstream reading the host validators used (scheme://authority
	// followed by the base path), so joining can never split userinfo, the
	// IPv6 brackets, the port or the base path differently than validation.
	parts := splitUpstream(route.Upstream)
	basePath := parts.basePath

	// Collapse only the junction run: all trailing slashes of the base
	// path meet all leading slashes of the remainder, and the junction
	// keeps exactly one slash whether or not anything follows them. A
	// remainder made entirely of slashes has no content past the run, so
	// it likewise ends in that single slash.
	baseTrimmed := strings.TrimRight(basePath, "/")
	rest := strings.TrimLeft(remainder, "/")
	joined := baseTrimmed + "/" + rest

	result := route.Upstream[:parts.schemeEnd+3] + parts.authority + joined
	query, f := applyQueryTransforms(route.QueryTransforms, target)
	if f != nil {
		return "", f
	}
	return result + query, nil
}

// validateTargetCharacters enforces on the raw target that only percent
// encoding may carry a space or a control character: a direct ASCII space
// (U+0020), a C0 control byte (U+0000 through U+001F) or DEL (U+007F) is
// rejected no matter whether it sits in the path, a parameter name or a
// parameter value. Bytes inside a well-formed percent escape ("%" plus two
// hex digits) are skipped, so "%20", "%0A" and "%09" keep parsing and
// matching on the raw encoded form; the rule never decodes an escape first.
// Invalid percent escapes are owned by validPercentEscapes, which runs
// before this check, so a lone or malformed "%" keeps its existing reason.
// The reason names the first offending character as U+XXXX.
func validateTargetCharacters(target string) *Failure {
	for i := 0; i < len(target); i++ {
		c := target[i]
		if c == '%' && i+2 < len(target) && isHex(target[i+1]) && isHex(target[i+2]) {
			// Skip a well-formed escape so an encoded space or control byte
			// is judged as data, never as a direct character. A malformed
			// escape is skipped byte by byte here; it is owned by the
			// validPercentEscapes check, which keeps its own earlier
			// reporting and must not let a following space be jumped over.
			i += 2
			continue
		}
		if c == ' ' || c < 0x20 || c == 0x7f {
			return failuref("invalid_request",
				"target contains a character that must be percent-encoded: U+%04X is not allowed to appear directly (percent-encode it, e.g. %%20 for a space)",
				c)
		}
	}
	return nil
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
