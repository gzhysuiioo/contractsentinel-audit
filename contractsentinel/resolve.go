// Offline route resolution: match a request against configured route prefixes
// and join the remainder onto the upstream base path without any network I/O.
package contractsentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Route is one configured route: an id, accepted methods, a path prefix and
// the upstream URL requests on that route are forwarded to. An optional
// queryTransforms list rewrites the request query string after the route has
// been selected.
type Route struct {
	ID              string            `json:"id"`
	Methods         []string          `json:"methods"`
	PathPrefix      string            `json:"pathPrefix"`
	Upstream        string            `json:"upstream"`
	QueryTransforms []*QueryTransform `json:"-"`

	// queryTransformsRaw holds the undecoded queryTransforms value between
	// Route.UnmarshalJSON and Config.UnmarshalJSON, which validates it once
	// the route's position in its own config is known.
	queryTransformsRaw json.RawMessage
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

// routeJSON mirrors Route, keeping queryTransforms as raw JSON so null,
// wrong types and malformed rules can be reported with the route's location
// instead of as a generic decode error.
type routeJSON struct {
	ID              string          `json:"id"`
	Methods         []string        `json:"methods"`
	PathPrefix      string          `json:"pathPrefix"`
	Upstream        string          `json:"upstream"`
	QueryTransforms json.RawMessage `json:"queryTransforms"`
}

// UnmarshalJSON decodes a route object and keeps queryTransforms raw; the
// enclosing Config.UnmarshalJSON validates it with the route's 1-based
// position in that config's routes array.
func (route *Route) UnmarshalJSON(data []byte) error {
	var rj routeJSON
	if err := json.Unmarshal(data, &rj); err != nil {
		return err
	}
	route.ID = rj.ID
	route.Methods = rj.Methods
	route.PathPrefix = rj.PathPrefix
	route.Upstream = rj.Upstream
	route.QueryTransforms = nil
	route.queryTransformsRaw = rj.QueryTransforms
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

// UnmarshalJSON decodes the routes array and validates each route's
// queryTransforms against that route's position in this config. The position
// comes from the array being decoded here, so configs parsed concurrently or
// interleaved in the same process cannot shift each other's route numbering.
func (cfg *Config) UnmarshalJSON(data []byte) error {
	var raw struct {
		Routes []Route `json:"routes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	cfg.Routes = raw.Routes
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

// ParseRequest parses and validates one JSON request.
func ParseRequest(data []byte) (*Request, *Failure) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, failuref("invalid_request", "request is not valid JSON: %v", err)
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
// junction. The base path is carried over byte for byte: joining never
// re-encodes, reorders or drops anything outside that junction. The raw
// query is preserved verbatim unless the route defines queryTransforms, in
// which case they rewrite it after route selection.
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
	joined := strings.TrimSuffix(basePath, "/")
	if remainder == "" {
		joined += "/" // the junction slash is kept even with no remaining path
	} else {
		joined += remainder
	}

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
