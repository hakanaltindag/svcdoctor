package diagnosis

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidRuleID reports that a string does not name a rule.
var ErrInvalidRuleID = errors.New("invalid rule id")

// maxRuleIDPart bounds each half of an identifier.
//
// It exists so that a fuzzer cannot drive allocation through this constructor
// and so that an identifier stays readable in a test name and a failure message.
// Nothing in the model needs a longer one.
const maxRuleIDPart = 48

// RuleID is a rule's stable identity, written "<owner>/<name>".
//
// For example "transport/dns". The owner is the package that owns the reasoning
// and the name is what the rule concludes about.
//
// # Why an identity exists at all
//
// Three consumers need one, and none of them can use a Go function value:
//
//   - duplicate detection at wiring time, so one rule cannot silently shadow
//     another (ADR 0080 section 2.4);
//   - a deterministic tie-break when two rules converge on one conclusion, so
//     that wiring order never reaches the output (ADR 0081 section 2.6);
//   - test names and debugging, where "which rule said this" has to be
//     answerable without a debugger.
//
// # Why it is not in the report
//
// It is not serialized. run.svcdoctorVersion already identifies the producer of
// a report, and naming rules in JSON would make every rule name a public
// interface that could not be renamed afterwards. ADR 0080 section 2.5 records
// the revisit condition: a support workflow that must ask "which rule said
// this" about a report from a version nobody has.
//
// # The representation
//
// Both halves are lower-case ASCII words separated by single hyphens, matching
// [a-z][a-z0-9]*(-[a-z0-9]+)*. That is deliberately narrower than "any string":
//
//   - it is derived from nothing at runtime, so no address, hash, pointer,
//     clock reading or map iteration can reach it;
//   - it sorts by bytes the same way it sorts by meaning, which is what makes
//     the merge tie-break in ADR 0081 section 2.6 stable rather than merely
//     defined;
//   - case folding and Unicode confusables cannot make two different rules look
//     like one, or one rule look like two.
//
// The zero RuleID is invalid. Use NewRuleID.
type RuleID string

// NewRuleID validates s and returns it as a rule identity.
//
// It is a plain constructor rather than a parser with options: there is one
// spelling of a rule identity and no dialect to negotiate.
func NewRuleID(s string) (RuleID, error) {
	owner, name, found := strings.Cut(s, "/")
	if !found {
		return "", fmt.Errorf(
			"%w: %q must be written \"<owner>/<name>\"", ErrInvalidRuleID, s)
	}
	// Cut splits at the first separator, so a second one lands in name and is
	// rejected there. Checking explicitly gives the better message.
	if strings.Contains(name, "/") {
		return "", fmt.Errorf(
			"%w: %q has more than one \"/\"", ErrInvalidRuleID, s)
	}
	if err := validateRuleIDPart("rule owner", owner); err != nil {
		return "", err
	}
	if err := validateRuleIDPart("rule name", name); err != nil {
		return "", err
	}
	return RuleID(s), nil
}

// validateRuleIDPart enforces [a-z][a-z0-9]*(-[a-z0-9]+)* within the length
// bound.
//
// It is written as an explicit scan rather than a regexp because
// internal/diagnosis reaches for no machinery it does not need, and because a
// scan reports which character was wrong.
func validateRuleIDPart(label, s string) error {
	switch {
	case s == "":
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidRuleID, label)
	case len(s) > maxRuleIDPart:
		return fmt.Errorf("%w: %s must be at most %d bytes, got %d",
			ErrInvalidRuleID, label, maxRuleIDPart, len(s))
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			continue
		case c >= '0' && c <= '9':
			if i == 0 {
				return fmt.Errorf("%w: %s %q must start with a letter",
					ErrInvalidRuleID, label, s)
			}
		case c == '-':
			// A hyphen separates words, so it may neither lead, trail, nor
			// double. Without this an identity would have several spellings.
			if i == 0 || i == len(s)-1 || s[i-1] == '-' {
				return fmt.Errorf(
					"%w: %s %q must separate words with single inner hyphens",
					ErrInvalidRuleID, label, s)
			}
		default:
			return fmt.Errorf(
				"%w: %s %q must be lower-case letters, digits and hyphens",
				ErrInvalidRuleID, label, s)
		}
	}
	return nil
}

// Valid reports whether id is a well-formed identity.
func (id RuleID) Valid() bool {
	_, err := NewRuleID(string(id))
	return err == nil
}

// Owner returns the part before the "/", or "" for an invalid identity.
func (id RuleID) Owner() string {
	owner, _, found := strings.Cut(string(id), "/")
	if !found {
		return ""
	}
	return owner
}

// Name returns the part after the "/", or "" for an invalid identity.
func (id RuleID) Name() string {
	_, name, found := strings.Cut(string(id), "/")
	if !found {
		return ""
	}
	return name
}

// String returns the identity as written.
func (id RuleID) String() string { return string(id) }
