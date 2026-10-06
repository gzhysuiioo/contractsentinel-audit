// Package contractsentinel rulefields: raw JSON type gates for the formal
// members of a rule definition, shared by the audit submission and the stored
// report archive.
package contractsentinel

import "encoding/json"

// ruleFieldType is the JSON type a written formal rule member must carry.
type ruleFieldType int

const (
	ruleFieldBoolean ruleFieldType = iota // the value must be JSON true or false
	ruleFieldString                       // the value must be a JSON string
)

// requirement is the trailing wording of the type error for this kind.
func (t ruleFieldType) requirement() string {
	switch t {
	case ruleFieldBoolean:
		return "must be a boolean"
	case ruleFieldString:
		return "must be a string"
	}
	return ""
}

// matches reports whether token — the value json.Unmarshal produced from the
// raw member — carries this JSON type.
func (t ruleFieldType) matches(token any) bool {
	switch t {
	case ruleFieldBoolean:
		_, ok := token.(bool)
		return ok
	case ruleFieldString:
		_, ok := token.(string)
		return ok
	}
	return false
}

// ruleFieldTypeCheck names one formal rule member and the JSON type its value
// must have whenever the member is written out. An omitted member is not
// checked here: it keeps decoding to its zero value and stays subject to the
// existing default and business-rule handling.
type ruleFieldTypeCheck struct {
	field string
	typ   ruleFieldType
}

// ruleFieldTypeHooks adapt the shared type gate to one entry point. locate
// renders the locator of the object at index i (the submission names only the
// rule, the archive also names its position in the rules or findings array);
// invalidJSON classifies a strict document that does not decode at all; reject
// reports the first written member whose raw JSON value carries another type.
type ruleFieldTypeHooks struct {
	locate      func(i int, obj map[string]json.RawMessage) string
	invalidJSON func(err error) error
	reject      func(where, field string, typ ruleFieldType) error
}

// checkRuleFieldTypes inspects the raw JSON token of every checked formal
// member of every strict rule, before the document is decoded into Go
// bool/string struct fields where null would silently become the zero value
// false or "" and launder an illegal submission or archive into a legal one.
// It is the rules-array specialization of checkObjectArrayFieldTypes shared by
// the audit submission and the stored report read: the written-means-typed
// rule, omission handling, per-object and per-member order, and the treatment
// of extension members all live there, while each side supplies its own array
// name, locator and error attribution. The strict rewrite has already dropped
// extension members, so only the agreed spelling (Unicode escapes included) is
// visible here — a case-variant or whitespace-padded name can neither supply
// nor rescue a formal value, and a null it carries never reaches this gate.
func checkRuleFieldTypes(strict []byte, checks []ruleFieldTypeCheck, hooks ruleFieldTypeHooks) error {
	return checkObjectArrayFieldTypes(strict, "rules", checks, hooks)
}

// formalRuleID returns the decoded value of a rule's formal id member when it
// is present and itself a legal non-empty JSON string; otherwise it returns
// "", so a rule with a missing, empty or mistyped id is located by its other
// context alone.
func formalRuleID(rule map[string]json.RawMessage) string {
	return formalMemberString(rule, "id")
}

// formalCheckRuleID returns the decoded value of a check record's formal
// ruleId member when it is present and itself a legal non-empty JSON string;
// otherwise it returns "", so a record with a missing, empty or mistyped
// ruleId is located by its checks-array position alone.
func formalCheckRuleID(rec map[string]json.RawMessage) string {
	return formalMemberString(rec, "ruleId")
}

// formalFindingRuleID returns the decoded value of a finding record's formal
// ruleId member when it is present and itself a legal non-empty JSON string;
// otherwise it returns "", so a finding with a missing, empty or mistyped
// ruleId is located by its findings-array position alone.
func formalFindingRuleID(rec map[string]json.RawMessage) string {
	return formalMemberString(rec, "ruleId")
}

// formalMemberString returns the decoded string value of obj's named formal
// member when the member is present and itself a legal JSON string; a missing
// member, a non-string value or an empty string all yield "".
func formalMemberString(obj map[string]json.RawMessage, name string) string {
	raw, ok := obj[name]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return ""
	}
	return value
}

// checkObjectArrayFieldTypes is checkRuleFieldTypes generalized over the
// top-level array carrying the fixed-shape objects: "rules" on both sides,
// "checks" on the submission side and "findings" on the archive read side
// share the same written-means-typed walk, while each gate supplies the array
// name, locator and error attribution.
func checkObjectArrayFieldTypes(strict []byte, arrayName string, checks []ruleFieldTypeCheck, hooks ruleFieldTypeHooks) error {
	var top struct {
		Rules    []map[string]json.RawMessage `json:"rules"`
		Checks   []map[string]json.RawMessage `json:"checks"`
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(strict, &top); err != nil {
		return hooks.invalidJSON(err)
	}
	objects := top.Rules
	switch arrayName {
	case "checks":
		objects = top.Checks
	case "findings":
		objects = top.Findings
	}
	for i, obj := range objects {
		where := hooks.locate(i, obj)
		for _, check := range checks {
			raw, present := obj[check.field]
			if !present {
				continue
			}
			var token any
			if err := json.Unmarshal(raw, &token); err != nil || !check.typ.matches(token) {
				return hooks.reject(where, check.field, check.typ)
			}
		}
	}
	return nil
}
