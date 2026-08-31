package config

import (
	"fmt"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// MaxTargetIDBytes bounds a target identifier.
//
// ADR 0071 section 5.2 derives it from the DNS label limit rather than choosing
// a round number: at 63 bytes an identifier can be used as a filename component,
// a label value and a JSON key with no escaping, in every consumer this project
// can foresee.
const MaxTargetIDBytes = 63

// TargetID is a target's identifier, validated.
//
// # The grammar
//
//	1*63( lowercase letter / digit / "-" / "_" ), starting and ending with a
//	letter or digit
//
// # Case is enforced, never folded
//
// `Orders-DB` is an error rather than a synonym for `orders-db`. This is
// domain.ServiceID's decision applied unchanged — *"case is fixed so that Kafka
// and kafka cannot both appear and split what should be one service in every
// report and every dashboard query"*. Folding would create two spellings of one
// thing, which is the failure internal/app's host normalization exists to
// prevent, and it would make duplicate detection depend on a normalization step
// a reader cannot see in the file.
//
// The zero TargetID is invalid.
type TargetID string

// NewTargetID validates an identifier.
func NewTargetID(s string) (TargetID, error) {
	if s == "" {
		return "", newError(CategoryInvalidField,
			"a target identifier is required; it is written rather than derived, because an "+
				"identifier taken from list position moves when a target is inserted above it, "+
				"and one taken from host:port cannot tell two targets on the same endpoint apart")
	}
	if len(s) > MaxTargetIDBytes {
		return "", newError(CategoryInvalidField, fmt.Sprintf(
			"target identifier is %d bytes, above the %d byte maximum", len(s), MaxTargetIDBytes))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '_':
			if i == 0 || i == len(s)-1 {
				return "", newError(CategoryInvalidField, fmt.Sprintf(
					"target identifier %q must start and end with a lowercase letter or a digit",
					s))
			}
		case c >= 'A' && c <= 'Z':
			return "", newError(CategoryInvalidField, fmt.Sprintf(
				"target identifier %q must be lowercase; it is refused rather than folded, so "+
					"that one target cannot appear under two spellings", s))
		default:
			return "", newError(CategoryInvalidField, fmt.Sprintf(
				"target identifier %q may hold only lowercase letters, digits, \"-\" and \"_\"",
				s))
		}
	}
	return TargetID(s), nil
}

// String returns the identifier.
func (id TargetID) String() string { return string(id) }

// UnmarshalYAML decodes and validates an identifier in one step.
func (id *TargetID) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
		return newError(CategoryInvalidField, fmt.Sprintf(
			"a target identifier must be a quoted or plain string, and %s was written instead",
			describeKind(value))).onLine(value.Line)
	}
	parsed, err := NewTargetID(value.Value)
	if err != nil {
		return withLine(err, value.Line)
	}
	*id = parsed
	return nil
}

// Duration is a configuration duration such as "30s" or "2m".
//
// go.yaml.in/yaml/v3 has no native time.Duration support, so without this a
// duration would have to be written as a bare integer count of nanoseconds.
type Duration time.Duration

// UnmarshalYAML parses a duration string.
//
// # A bare number is refused
//
// `timeout: 30` names no unit, and the two readings a reader might have —
// thirty seconds, thirty nanoseconds — differ by nine orders of magnitude. Go's
// own default would make it nanoseconds, which is never what an operator meant.
// Refusing costs one character and removes the reading that silently produces a
// run that times out instantly.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
		return newError(CategoryInvalidField, fmt.Sprintf(
			"a duration must be written with a unit, such as \"30s\" or \"2m\", and %s was "+
				"written instead", describeKind(value))).onLine(value.Line)
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return newError(CategoryInvalidField, fmt.Sprintf(
			"%q is not a duration; write it with a unit, such as \"30s\" or \"2m\"",
			value.Value)).onLine(value.Line)
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String renders the duration.
func (d Duration) String() string { return time.Duration(d).String() }

// TLS is the transport-encryption block.
//
// # Why this is generic, and why that is a finding rather than an assumption
//
// ADR 0071 section 7.3. internal/cli/tls.go is already a single file holding the
// whole TLS-flag contract for all four services, and it says so: *"The four are
// identical across services on purpose, and grouping them makes that a fact of
// the type rather than a coincidence of two flag sets."* ADR 0060 forced that
// unification after finding the contract in two places where the two disagreed.
//
// So the **block** is generic and so is the refusal of the last three fields
// under `mode: disable`. What `require` means on the wire is service-owned and
// stays where it already is — an in-band SSLRequest negotiation for PostgreSQL,
// an ordinary handshake for the other three.
type TLS struct {
	// Mode is "require" or "disable". Empty means "require", which is every leaf
	// command's default.
	Mode string `yaml:"mode"`

	// CAFile replaces the system trust store; it never extends it (ADR 0058 §2).
	CAFile string `yaml:"ca_file"`

	// ServerName is the identity to verify, overriding the host.
	ServerName string `yaml:"server_name"`

	// Insecure disables peer identity verification. It is an explicit per-run
	// opt-in, recorded in the report, and never an automatic fallback.
	Insecure bool `yaml:"insecure"`
}

// Enabled reports whether a handshake is planned.
func (t TLS) Enabled() bool { return t.Mode != "disable" }

// validate enforces the mode vocabulary and ADR 0060's inert-flag refusal.
//
// # Refusal rather than silent acceptance
//
// `mode: disable` with `ca_file` set describes a run with no handshake to apply
// a trust source to, and `mode: disable` with `insecure: true` describes a run
// with no verification to disable. Accepting either lets an operator believe
// they configured — or deliberately relaxed — the security of a connection that
// was never going to be encrypted at all. The second is the worse: someone who
// wrote `insecure` believes they are running an unverified TLS connection, and
// they are running no TLS connection.
//
// One field per message, in a fixed order, because the three do not interact and
// listing them together reads as though they do.
func (t TLS) validate() *Error {
	switch t.Mode {
	case "", "require", "disable":
	default:
		return newError(CategoryInvalidField, fmt.Sprintf(
			"tls.mode %q must be \"require\" or \"disable\"", t.Mode))
	}
	if t.Enabled() {
		return nil
	}
	switch {
	case t.CAFile != "":
		return newError(CategoryInvalidField,
			"tls.ca_file has no effect with tls.mode \"disable\"")
	case t.ServerName != "":
		return newError(CategoryInvalidField,
			"tls.server_name has no effect with tls.mode \"disable\"")
	case t.Insecure:
		return newError(CategoryInvalidField,
			"tls.insecure has no effect with tls.mode \"disable\"")
	}
	return nil
}
