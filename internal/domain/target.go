package domain

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Target describes what the user asked svcdoctor to inspect.
//
// It records both what was requested and what normalization turned it into, so
// a reader can tell the difference between what was typed and what was actually
// inspected. See docs/REPORT_SCHEMA.md section 3.
//
// # Target is not Subject
//
// A Subject identifies what a single piece of evidence is about. A Target
// identifies the whole diagnostic request. One report has one target and many
// subjects.
//
// # Service neutrality
//
// There is no target kind and no per-service target type. A Kafka bootstrap list
// and a PostgreSQL multi-host DSN are both "what was asked for", and what kind
// of thing it is, is already recorded as the run's service. Adding
// KafkaTarget or PostgresTarget would put service semantics in the core.
//
// # Credentials
//
// > The canonical report must never contain plaintext credentials.
//
// Both fields are plain text and this type cannot inspect them for secrets. The
// contract is therefore on the producer: whatever performs L0 normalization must
// hand over a form with credential material already removed, not merely masked
// for display. A DSN reaches this type without its password or it does not reach
// it at all. This type accepts no security.Secret and no security.Credential, so
// there is no field through which credential material could arrive intact.
//
// The zero Target is invalid. Use NewTarget.
type Target struct {
	requested  string
	normalized []string
}

// NewTarget records a diagnostic request.
//
// requested is the credential-free form of what the user asked for and is
// required. normalized is what L0 normalization produced, for example the
// individual bootstrap endpoints a single argument expanded into. It is optional
// because normalization can fail while a report is still produced, and it is
// copied so the caller's slice cannot alter the target afterwards.
func NewTarget(requested string, normalized ...string) (Target, error) {
	if err := validateIdentifier("target request", requested); err != nil {
		return Target{}, err
	}
	for _, n := range normalized {
		if err := validateIdentifier("normalized target", n); err != nil {
			return Target{}, err
		}
	}
	return Target{requested: requested, normalized: slices.Clone(normalized)}, nil
}

// Requested returns the credential-free form of what the user asked for.
func (t Target) Requested() string { return t.requested }

// Normalized returns a copy of what normalization produced, which may be empty.
func (t Target) Normalized() []string {
	if len(t.normalized) == 0 {
		return nil
	}
	return slices.Clone(t.normalized)
}

// IsZero reports whether t is the invalid zero Target.
func (t Target) IsZero() bool { return t.requested == "" }

// String returns the requested form.
func (t Target) String() string {
	if t.IsZero() {
		return "<invalid target>"
	}
	return t.requested
}

// MarshalJSON emits the target as an object.
//
// A custom marshaler is required rather than merely convenient: the fields are
// unexported to keep the value immutable, so the default encoding would be "{}".
func (t Target) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return nil, fmt.Errorf("%w: zero Target", ErrInvalidValue)
	}
	return json.Marshal(struct {
		Requested  string   `json:"requested"`
		Normalized []string `json:"normalized,omitempty"`
	}{Requested: t.requested, Normalized: t.normalized})
}
