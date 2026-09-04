package diagnosis

import (
	"errors"
	"fmt"
	"slices"
)

// ErrInvalidRuleSet reports that a described rule set cannot be frozen.
//
// It is distinct from ErrInvalidRuleID: that one means a single identity is not
// well formed, while this one means the identities are individually fine and the
// set they describe is not — most often because two rules claim one identity.
var ErrInvalidRuleSet = errors.New("invalid rule set")

// RegisteredRule is one rule and the identity it was wired in under.
//
// Rule stays a bare function type (ADR 0080 section 2.1), so a function value
// cannot carry an identity of its own: every rule has the same Go type and there
// is no honest way to recover a name from one. The pairing is therefore made
// explicitly, at the composition root, which is also the only place that knows
// which rules a service needs.
//
// The zero RegisteredRule is invalid.
type RegisteredRule struct {
	id   RuleID
	eval Rule
}

// ID returns the rule's identity.
func (r RegisteredRule) ID() RuleID { return r.id }

// Eval returns the rule itself.
func (r RegisteredRule) Eval() Rule { return r.eval }

// IsZero reports whether r is the invalid zero RegisteredRule.
func (r RegisteredRule) IsZero() bool { return r.id == "" && r.eval == nil }

// RuleSet accumulates rules and produces an immutable Registry.
//
// The mutable builder and the immutable Registry are separate types for the same
// reason GraphBuilder and Graph are: a single type carrying both a frozen flag
// and mutation methods would leave immutability to discipline, and here it is
// enforced because Registry simply has no way to change.
//
// A RuleSet is not safe for concurrent use. It is built once, at a composition
// root, on one goroutine. A frozen Registry is safe for concurrent reads and may
// be shared by every target of a fleet run, which is what ADR 0073's executor
// actually needs.
//
// # Why the error is deferred to Freeze
//
// GraphBuilder returns an error from every mutator, because its callers add
// nodes in loops over data discovered at run time and have to react to each one.
// A rule set is the opposite: a fixed, hand-written list, wired once, whose
// every failure mode is a build-time mistake. Chaining keeps the composition
// readable as the list it is, and the error cannot be dropped because Freeze is
// the only way to obtain a Registry.
//
// The zero RuleSet is valid and empty; NewRuleSet is the ordinary way to get one.
type RuleSet struct {
	rules []RegisteredRule

	// seen makes duplicate detection independent of how many rules were added.
	// It never reaches the output: ordering comes from rules alone, so no map
	// iteration can affect a Registry.
	seen map[RuleID]struct{}

	// err is the first failure. Later failures are not collected: the first one
	// names a concrete mistake in a fixed list, and a caller fixes it and runs
	// again.
	err error
}

// NewRuleSet returns an empty rule set.
func NewRuleSet() *RuleSet { return &RuleSet{} }

// Add registers eval under the identity named by id and returns s for chaining.
//
// The identity is supplied as a string and validated here so that no caller ever
// holds an unvalidated RuleID. A nil rule is rejected rather than skipped: a nil
// rule is a wiring mistake, and quietly ignoring it would produce a report
// missing findings nobody noticed were absent.
//
// A repeated identity is rejected even when the rule is the same function. There
// is no merge and no last-write-wins, because a silent overwrite is exactly the
// failure ADR 0080 section 2.4 exists to prevent: one rule shadowing another
// while the wiring reads as though both ran.
func (s *RuleSet) Add(id string, eval Rule) *RuleSet {
	if s.err != nil {
		return s
	}

	ruleID, err := NewRuleID(id)
	if err != nil {
		s.err = err
		return s
	}
	if eval == nil {
		s.err = fmt.Errorf("%w: rule %q is nil", ErrInvalidRuleSet, ruleID)
		return s
	}
	if _, exists := s.seen[ruleID]; exists {
		s.err = fmt.Errorf("%w: rule %q is already registered", ErrInvalidRuleSet, ruleID)
		return s
	}

	if s.seen == nil {
		s.seen = make(map[RuleID]struct{})
	}
	s.seen[ruleID] = struct{}{}
	s.rules = append(s.rules, RegisteredRule{id: ruleID, eval: eval})
	return s
}

// Len reports how many rules have been added so far.
func (s *RuleSet) Len() int { return len(s.rules) }

// Err returns the first failure recorded by Add, or nil.
func (s *RuleSet) Err() error { return s.err }

// Freeze returns an immutable Registry holding the rules added so far.
//
// A rule set may be frozen more than once. Each Freeze returns an independent
// Registry, and later additions leave earlier registries untouched.
//
// Freeze is where a rule set becomes a contract, so it is where the set-level
// invariant is rechecked rather than assumed. Add already refuses a duplicate
// identity, which is strictly earlier and names the offending call; a Registry
// that could nonetheless hold two rules under one identity would make the merge
// tie-break of ADR 0081 section 2.6 undefined, and that is too load-bearing to
// rest on one check.
func (s *RuleSet) Freeze() (Registry, error) {
	if s.err != nil {
		return Registry{}, s.err
	}

	seen := make(map[RuleID]struct{}, len(s.rules))
	out := make([]RegisteredRule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.IsZero() {
			return Registry{}, fmt.Errorf(
				"%w: the zero rule cannot be registered", ErrInvalidRuleSet)
		}
		if !r.id.Valid() {
			return Registry{}, fmt.Errorf("%w: rule id %q", ErrInvalidRuleID, r.id)
		}
		if r.eval == nil {
			return Registry{}, fmt.Errorf("%w: rule %q is nil", ErrInvalidRuleSet, r.id)
		}
		if _, dup := seen[r.id]; dup {
			return Registry{}, fmt.Errorf(
				"%w: rule %q is registered twice", ErrInvalidRuleSet, r.id)
		}
		seen[r.id] = struct{}{}
		out = append(out, r)
	}
	return Registry{rules: slices.Clip(out)}, nil
}

// Registry is an immutable, ordered set of identified rules.
//
// It is what a composition root assembles and what an Engine evaluates. It has
// no mutation methods, and every accessor that returns a slice returns a copy,
// so a caller cannot reach the internal structure. Because it exposes no mutable
// state, a frozen Registry is safe for concurrent reads and may be shared across
// every target in a fleet run without synchronization; none is added here.
//
// # Ordering
//
// Registration order is preserved, and it is the order rules are evaluated in.
// That is a readability property for whoever reads the composition, not an
// output property: findings leave the engine in the canonical order
// domain.SortFindings defines, so wiring order cannot reach a report.
//
// The zero Registry is valid and has no rules.
type Registry struct {
	rules []RegisteredRule
}

// Len returns how many rules the registry holds.
func (r Registry) Len() int { return len(r.rules) }

// Rules returns a copy of the registered rules in registration order.
func (r Registry) Rules() []RegisteredRule {
	if len(r.rules) == 0 {
		return nil
	}
	return slices.Clone(r.rules)
}

// IDs returns the registered identities in registration order.
//
// It is the cheap way to describe a registry in a test or a failure message. It
// is deliberately not sorted: a caller that wants sorted identities can sort a
// copy, and wiring order is what makes a diff against the composition root
// readable.
func (r Registry) IDs() []RuleID {
	if len(r.rules) == 0 {
		return nil
	}
	out := make([]RuleID, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule.id)
	}
	return out
}

// Has reports whether id is registered.
//
// The scan is linear over a set that is fixed at build time and holds fewer than
// a dozen entries in every wiring that exists. An index would be a map, and a
// map in this type is one more thing that must be proven not to reach the
// output.
func (r Registry) Has(id RuleID) bool {
	for _, rule := range r.rules {
		if rule.id == id {
			return true
		}
	}
	return false
}
