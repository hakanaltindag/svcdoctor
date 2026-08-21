package domain

import (
	"encoding/json"
	"fmt"
)

// Recommendation is one suggested next action attached to a finding.
//
// It is inert report data. It is not a task, not a script, and not something
// svcdoctor executes: there is no command to run, no remediation to apply, and
// no workflow to advance. A reader decides what to do with it.
//
// The type holds a single action today. It is a struct rather than a bare string
// so that the encoded form is an object from the outset, which lets fields such
// as a reference link or a remediation risk be added later without changing the
// shape of every existing report. Those fields are deliberately absent for now:
// docs/FINDINGS.md lists them as "recommended when relevant", nothing consumes
// them yet, and no renderer exists to display them.
//
// The zero Recommendation is invalid. Use NewRecommendation.
type Recommendation struct {
	action string
}

// NewRecommendation validates a suggested action.
//
// The action is a single line of human-readable text. It is validated only as a
// value: nothing here contacts a network, resolves a link, or checks that the
// advice is applicable.
func NewRecommendation(action string) (Recommendation, error) {
	if err := validateIdentifier("recommendation action", action); err != nil {
		return Recommendation{}, err
	}
	return Recommendation{action: action}, nil
}

// Action returns the suggested action text.
func (r Recommendation) Action() string { return r.action }

// IsZero reports whether r is the invalid zero Recommendation.
func (r Recommendation) IsZero() bool { return r == Recommendation{} }

// String returns the action text.
func (r Recommendation) String() string {
	if r.IsZero() {
		return "<invalid recommendation>"
	}
	return r.action
}

// MarshalJSON emits the recommendation as an object.
//
// A custom marshaler is required rather than merely convenient: the field is
// unexported to keep the value immutable, so the default encoding would be "{}".
func (r Recommendation) MarshalJSON() ([]byte, error) {
	if r.IsZero() {
		return nil, fmt.Errorf("%w: zero Recommendation", ErrInvalidValue)
	}
	return json.Marshal(struct {
		Action string `json:"action"`
	}{Action: r.action})
}
