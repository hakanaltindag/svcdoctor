package domain

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// EvidenceID identifies one evidence node within a single run.
//
// It is supplied by the caller, never generated here. This package has no
// clock, no random source, and no network access, so it cannot produce an
// identifier that is stable across runs; only the code that knows the shape of
// the run can. The scheme that builds these identifiers is graph work and is
// not defined in this phase.
//
// The type is a string so that it is directly comparable, usable as a map key,
// and encodes as a plain JSON string.
type EvidenceID string

// NewEvidenceID validates an already-normalized identifier.
//
// The rules are deliberately permissive about structure and strict about
// determinism, because the identifier scheme is not fixed yet:
//
//   - It must not be empty.
//   - It must be valid UTF-8, so that encoding never substitutes replacement
//     characters and change the identifier.
//   - It must contain no control characters, which would corrupt JSON and
//     terminal output.
//   - It must have no leading or trailing whitespace. Surrounding space is
//     rejected rather than trimmed, because trimming would silently map two
//     different inputs onto the same identifier.
func NewEvidenceID(s string) (EvidenceID, error) {
	if err := validateIdentifier("evidence id", s); err != nil {
		return "", err
	}
	return EvidenceID(s), nil
}

// Valid reports whether id satisfies the rules documented on NewEvidenceID.
func (id EvidenceID) Valid() bool {
	return validateIdentifier("evidence id", string(id)) == nil
}

// String returns the identifier text.
func (id EvidenceID) String() string { return string(id) }

// validateIdentifier applies the shared rules for caller-supplied identifier
// text. label names the field in the returned error.
func validateIdentifier(label, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidValue, label)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidValue, label)
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrInvalidValue, label)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidValue, label)
		}
	}
	return nil
}
