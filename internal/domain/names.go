package domain

import (
	"fmt"
	"strings"
)

// Step names the operation that produced a piece of evidence, for example
// "dns.lookup", "tcp.connect", or "protocol.capabilities".
//
// It is a validated string rather than an enumeration on purpose. A closed set
// would have to name every operation of every present and future service in the
// core. That is the same central-enumeration coupling that docs/FINDINGS.md
// rejects for finding codes, in a different shape. A service adapter can
// introduce "kafka.api_versions" without any change here and without core
// branching.
type Step string

// AttributeKey names one normalized attribute on an evidence node, for example
// "dns.rcode" or "tls.negotiated_version".
//
// This is the generic key type only. Where service-specific key constants live
// is an open decision, deliberately not settled here. There is no central
// registry of service attribute keys in this package, and there must not be one:
// that would recreate the coupling the architecture avoids for finding codes.
type AttributeKey string

// NewStep validates an operation name.
func NewStep(s string) (Step, error) {
	if err := validateDottedName("step", s); err != nil {
		return "", err
	}
	return Step(s), nil
}

// Valid reports whether s satisfies the dotted-name rules.
func (s Step) Valid() bool { return validateDottedName("step", string(s)) == nil }

// String returns the step text.
func (s Step) String() string { return string(s) }

// NewAttributeKey validates an attribute key.
func NewAttributeKey(s string) (AttributeKey, error) {
	if err := validateDottedName("attribute key", s); err != nil {
		return "", err
	}
	return AttributeKey(s), nil
}

// Valid reports whether k satisfies the dotted-name rules.
func (k AttributeKey) Valid() bool { return validateDottedName("attribute key", string(k)) == nil }

// String returns the key text.
func (k AttributeKey) String() string { return string(k) }

// validateDottedName enforces the shared grammar for steps and attribute keys:
//
//	segment    = 1*( lowercase letter / digit / "_" )
//	dottedName = segment *( "." segment )
//
// Case is fixed to lowercase so that "DNS.Lookup" and "dns.lookup" cannot both
// exist and split what should be one key. The grammar is restrictive because
// these strings are part of the report contract and are matched by automation.
func validateDottedName(label, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidValue, label)
	}
	for _, segment := range strings.Split(s, ".") {
		if segment == "" {
			return fmt.Errorf("%w: %s %q has an empty segment", ErrInvalidValue, label, s)
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			switch {
			case c >= 'a' && c <= 'z',
				c >= '0' && c <= '9',
				c == '_':
			default:
				return fmt.Errorf(
					"%w: %s %q may contain only lowercase letters, digits, underscore and dots",
					ErrInvalidValue, label, s)
			}
		}
	}
	return nil
}
