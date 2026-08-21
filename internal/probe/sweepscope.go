package probe

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidSweepScope reports that a scope label cannot be used.
var ErrInvalidSweepScope = errors.New("invalid sweep scope")

// SweepScope distinguishes two measurements that observe the same thing.
//
// A run can legitimately measure one hostname more than once. A bootstrap sweep
// resolves `broker.internal`, and later a topology sweep resolves it again
// because the cluster advertised it — two executions, at two moments, for two
// reasons, of the same subject. Both are true, and a diagnostic tool that could
// only record one of them would be hiding the disagreement it exists to find.
//
// Evidence identifiers are derived from what a node is about (ADR 0019), so
// those two lookups mint the same identifier and the graph rejects the second.
// That rejection is correct — the identifiers really were the same — and ADR
// 0019 recorded the gap it exposes under "Topology", predicting that
// "GraphBuilder failing loudly on a duplicate […] surfaces the question at the
// moment something first needs it". This type is the answer to that question.
//
// # What it is
//
// An opaque label naming *which execution* a measurement belongs to. It is
// chosen by whoever orchestrates the run, carried unchanged through the probes,
// and used for exactly one thing: a component of the evidence identifier.
//
// # What it is not
//
//   - **Not `Origin`.** It does not say a subject was user-supplied or
//     discovered. Two sweeps may have any relationship or none, and a scope
//     label is not a claim about how anything entered the run. `Origin` remains
//     deferred (ADR 0013, ADR 0031).
//   - **Not endpoint identity.** It never names a host, an address or a port,
//     and two scopes measuring one endpoint do not make it two endpoints.
//   - **Not a subject.** It never reaches `Subject`, and never reaches an
//     attribute. What was observed is unchanged by who asked; only the
//     identifier distinguishes the measurements.
//   - **Not interpreted.** No probe reads it, branches on it, or derives
//     anything from it. It is escaped and joined, and that is all.
//
// # The zero value is unscoped, and that is load-bearing
//
// A zero SweepScope adds no component, so an unscoped call mints byte-identical
// identifiers to the ones this repository has produced since Phase 2. Every
// existing producer stays unscoped and unchanged; scoping is something a caller
// opts into when it genuinely runs a second sweep.
//
// See ADR 0032.
type SweepScope struct {
	label string
}

// NewSweepScope validates a scope label.
//
// The rules are the ones an evidence identifier must satisfy, checked here so
// that a bad label fails at the call that chose it rather than several layers
// later inside NewEvidence.
//
// **The separator and the escape character are deliberately allowed.** ADR 0019
// is emphatic that "a delimiter choice must never decide what input a layer
// accepts": the encoding absorbs awkward characters instead of rejecting them,
// and a scope is no different. A label containing "/" or "%" is escaped like any
// other component and stays injective.
//
// An empty label is rejected rather than silently meaning "unscoped". A caller
// that wants no scope uses the zero value, which reads as the deliberate choice
// it is; a caller that computed an empty string has a bug worth surfacing.
func NewSweepScope(label string) (SweepScope, error) {
	switch {
	case label == "":
		return SweepScope{}, fmt.Errorf(
			"%w: label must not be empty; use the zero SweepScope for an unscoped sweep",
			ErrInvalidSweepScope)
	case !utf8.ValidString(label):
		return SweepScope{}, fmt.Errorf("%w: label must be valid UTF-8", ErrInvalidSweepScope)
	case strings.TrimSpace(label) != label:
		return SweepScope{}, fmt.Errorf(
			"%w: label must not have leading or trailing whitespace", ErrInvalidSweepScope)
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return SweepScope{}, fmt.Errorf(
				"%w: label must not contain control characters", ErrInvalidSweepScope)
		}
	}
	return SweepScope{label: label}, nil
}

// IsZero reports whether s is the unscoped zero value.
func (s SweepScope) IsZero() bool { return s.label == "" }

// String returns the label, or the empty string when unscoped.
func (s SweepScope) String() string { return s.label }
