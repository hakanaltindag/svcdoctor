package domain

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// SubjectKind says what sort of thing a piece of evidence is about.
//
// The set is minimal on purpose. This is not a generic resource model, and it
// must never grow a member per service: a Kafka broker and a PostgreSQL host
// are both endpoints, and what distinguishes them belongs in attributes.
//
// The zero SubjectKind is SubjectKindUnspecified.
type SubjectKind uint8

const (
	// SubjectKindUnspecified is the zero value and is not a kind.
	SubjectKindUnspecified SubjectKind = iota

	// SubjectKindTarget means the evidence is about the inspected target as a
	// whole rather than one of its endpoints, for example configuration
	// normalization at L0.
	SubjectKindTarget

	// SubjectKindEndpoint means the evidence is about a single endpoint.
	SubjectKindEndpoint
)

// subjectKindNames is indexed by SubjectKind. Keep it aligned with the const
// block above; TestSubjectKindNamesCoverAllKinds fails if the two drift apart.
var subjectKindNames = [...]string{
	SubjectKindUnspecified: "UNSPECIFIED",
	SubjectKindTarget:      "TARGET",
	SubjectKindEndpoint:    "ENDPOINT",
}

// Valid reports whether k is a defined kind. SubjectKindUnspecified is not.
func (k SubjectKind) Valid() bool {
	return k != SubjectKindUnspecified && int(k) < len(subjectKindNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (k SubjectKind) String() string {
	if int(k) >= len(subjectKindNames) {
		return "SubjectKind(" + strconv.FormatUint(uint64(k), 10) + ")"
	}
	return subjectKindNames[k]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (k SubjectKind) MarshalJSON() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("%w: SubjectKind(%d)", ErrInvalidValue, uint8(k))
	}
	return []byte(strconv.Quote(subjectKindNames[k])), nil
}

// Subject identifies what a piece of evidence is about.
//
// It carries a kind and a reference string, and nothing else. The reference is
// opaque normalized text supplied by the producer, such as "kafka.internal:9092"
// for an endpoint. It is not a security.Endpoint: that type exists to bind a
// credential and requires a port, whereas a subject is a label on a fact and may
// describe a whole target. Keeping them separate also keeps this package a leaf
// with no dependency on internal/security.
//
// There is deliberately no separate display field. For every subject this model
// can express, the reference is already the thing a reader wants to see.
//
// The zero Subject is invalid. Use NewTargetSubject or NewEndpointSubject.
type Subject struct {
	kind SubjectKind
	ref  string
}

// NewTargetSubject describes the inspected target as a whole.
func NewTargetSubject(ref string) (Subject, error) {
	return newSubject(SubjectKindTarget, ref)
}

// NewEndpointSubject describes a single endpoint.
func NewEndpointSubject(ref string) (Subject, error) {
	return newSubject(SubjectKindEndpoint, ref)
}

// newSubject is unexported so that no caller can construct a subject with an
// unspecified or out-of-range kind. A new kind gets its own constructor.
func newSubject(kind SubjectKind, ref string) (Subject, error) {
	if err := validateIdentifier("subject ref", ref); err != nil {
		return Subject{}, err
	}
	return Subject{kind: kind, ref: ref}, nil
}

// Kind reports what sort of thing the evidence is about.
func (s Subject) Kind() SubjectKind { return s.kind }

// Ref returns the normalized reference text.
func (s Subject) Ref() string { return s.ref }

// IsZero reports whether s is the invalid zero Subject.
func (s Subject) IsZero() bool { return s == Subject{} }

// String returns a readable rendering naming both the kind and the reference.
func (s Subject) String() string {
	if s.IsZero() {
		return "<invalid subject>"
	}
	return s.kind.String() + ":" + s.ref
}

// MarshalJSON emits the subject as an object.
//
// A custom marshaler is required rather than merely convenient: the fields are
// unexported to keep Subject immutable, so the default encoding would be "{}".
func (s Subject) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return nil, fmt.Errorf("%w: zero Subject", ErrInvalidValue)
	}
	return json.Marshal(struct {
		Kind SubjectKind `json:"kind"`
		Ref  string      `json:"ref"`
	}{Kind: s.kind, Ref: s.ref})
}
