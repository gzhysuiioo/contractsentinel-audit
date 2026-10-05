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
// renders the locator of the rule at index i (the submission names only the
// rule, the archive also names its position in the rules array); invalidJSON
// classifies a strict document that does not decode at all; reject reports the
// first written member whose raw JSON value carries another type.
type ruleFieldTypeHooks struct {
	locate      func(i int, rule map[string]json.RawMessage) string
	invalidJSON func(err error) error
	reject      func(where, field string, typ ruleFieldType) error
}

// checkRuleFieldTypes inspects the raw JSON token of every checked formal
// member of every strict rule, before the document is decoded into Go
// bool/string struct fields where null would silently become the zero value
// false or "" and launder an illegal submission or archive into a legal one.
// It is the single implementation behind the audit submission and the stored
// report read: the written-means-typed rule, omission handling, per-rule and
// per-member order, and the treatment of extension members all live here,
// while each side supplies its own locator and error attribution. The strict
// rewrite has already dropped extension members, so only the agreed spelling
// (Unicode escapes included) is visible here — a case-variant or
// whitespace-padded name can neither supply nor rescue a formal value, and a
// null it carries never reaches this gate.
func checkRuleFieldTypes(strict []byte, checks []ruleFieldTypeCheck, hooks ruleFieldTypeHooks) error {
	var top struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(strict, &top); err != nil {
		return hooks.invalidJSON(err)
	}
	for i, rule := range top.Rules {
		where := hooks.locate(i, rule)
		for _, check := range checks {
			raw, present := rule[check.field]
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

// formalRuleID returns the decoded value of a rule's formal id member when it
// is present and itself a legal non-empty JSON string; otherwise it returns
// "", so a rule with a missing, empty or mistyped id is located by its other
// context alone.
func formalRuleID(rule map[string]json.RawMessage) string {
	raw, ok := rule["id"]
	if !ok {
		return ""
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || id == "" {
		return ""
	}
	return id
}
