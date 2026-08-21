package domain

import (
	"fmt"
	"strings"
)

// FindingCode is the stable machine-consumed identifier of a finding.
//
// Codes follow the convention in docs/FINDINGS.md:
//
//	<NAMESPACE>_<DESCRIPTION>
//
// The namespace names the owner of the rule that produces the code. A rule owned
// by a service package is namespaced by its service, a rule owned by the
// transport diagnosis package is namespaced by its layer:
//
//	KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
//	POSTGRES_TLS_POLICY_MISMATCH
//	DNS_RESOLUTION_FAILED
//	TCP_CONNECTION_REFUSED
//
// The format is checked; the namespace set is not. Validation must never hold a
// list of known namespaces, because a future service would then have to edit
// core validation to introduce its own codes. That is the central-enumeration
// coupling docs/FINDINGS.md rejects.
//
// There is deliberately no catalog of codes in this package. Code constants live
// with the rules that produce them; the core knows only that a code is a
// namespaced string.
//
// A code and the text shown beside it are different contracts. Message text may
// improve freely. A code's meaning must stay stable once exposed, because
// automation matches on it; if the meaning has to change, introduce a new code.
type FindingCode string

// NewFindingCode validates a finding code.
//
// The grammar is deliberately strict about shape:
//
//	segment = 1*( uppercase letter / digit )
//	code    = segment 1*( "_" segment )
//
// At least two segments are required, which is what enforces the namespace
// convention without knowing any namespace. The first character must be a
// letter, so a code cannot begin with a digit.
func NewFindingCode(s string) (FindingCode, error) {
	if err := validateFindingCode(s); err != nil {
		return "", err
	}
	return FindingCode(s), nil
}

// Valid reports whether c satisfies the grammar documented on NewFindingCode.
func (c FindingCode) Valid() bool { return validateFindingCode(string(c)) == nil }

// String returns the code text.
func (c FindingCode) String() string { return string(c) }

// Namespace returns the leading segment of the code, for example "KAFKA" for
// "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE".
//
// It exists so that a renderer or a report summary can group findings by owner
// without parsing the code itself and without a lookup table. It returns the
// empty string for an invalid code.
func (c FindingCode) Namespace() string {
	if !c.Valid() {
		return ""
	}
	namespace, _, _ := strings.Cut(string(c), "_")
	return namespace
}

func validateFindingCode(s string) error {
	if s == "" {
		return fmt.Errorf("%w: finding code must not be empty", ErrInvalidValue)
	}
	if s[0] < 'A' || s[0] > 'Z' {
		return fmt.Errorf("%w: finding code %q must start with an uppercase letter", ErrInvalidValue, s)
	}

	segments := strings.Split(s, "_")
	if len(segments) < 2 {
		return fmt.Errorf(
			"%w: finding code %q must be <NAMESPACE>_<DESCRIPTION>", ErrInvalidValue, s)
	}
	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("%w: finding code %q has an empty segment", ErrInvalidValue, s)
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			switch {
			case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			default:
				return fmt.Errorf(
					"%w: finding code %q may contain only uppercase letters, digits and underscores",
					ErrInvalidValue, s)
			}
		}
	}
	return nil
}
