package diagnosis

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// RuleContext is everything a rule may see.
//
// Its smallness is the security model. A rule receives a frozen graph, the
// position the measurements were taken from, and one boolean. There is nothing
// here to dial, nothing to open, nothing to reveal and nothing to read the clock
// with, so "a rule cannot leak a credential" is a property of the type rather
// than a rule somebody has to remember. See ADR 0080 section 2.1 and section 5.
//
// # What is deliberately absent
//
// The absences are the contract, and each was argued rather than overlooked:
//
//   - no context.Context. There is nothing to cancel — evaluation is in-memory
//     and bounded by the size of the graph — and carrying one would invite the
//     I/O that ADR 0078 section 2.6 forbids.
//   - no ServiceID. The engine never hands a rule a service name to branch on.
//     A service rule is a rule that is only wired in for that service, which is
//     the same explicit composition ADR 0009 chose for services themselves.
//   - no credential, no configuration, no filesystem handle, no clock, no
//     random source.
//   - no Report. A report contains the findings a rule produces, so carrying one
//     would be circular (ADR 0017).
//
// # Why these three
//
// Graph is the evidence, and it was always the argument.
//
// Vantage is admitted because ADR 0012 makes a reachability claim a claim about
// a network position. A rule that marks a finding vantage-dependent should be
// able to say so from data rather than from a constant, and a later rule that
// needs to describe *which* position will find it here rather than inventing a
// second channel for it.
//
// Incomplete is admitted because a rule that cannot tell "not measured" from
// "measured and absent" will eventually state the stronger of the two. That
// defect has a name in this repository — less evidence must never produce a
// stronger claim — and it is worth one field to make the distinction reachable.
//
// # Why a struct
//
// The next admitted fact is a field rather than a signature change, so adding
// one does not touch every rule in the tree. Adding one is still a deliberate
// act: TestDIAG017RuleContextCarriesExactlyThreeFields fails when the field set
// changes, so a field arrives with a decision behind it.
//
// The zero RuleContext is valid: an empty graph, an unset vantage, and a run
// that was not cut short. Rules must tolerate it, because a rule that panics on
// an empty graph is a rule that panics on a run that measured nothing.
type RuleContext struct {
	// Graph is the frozen evidence. It is immutable and copies on read, so a
	// rule cannot change what another rule sees.
	Graph domain.Graph

	// Vantage records where the evidence was collected from. It may be the zero
	// Vantage when the caller did not record one; a rule must not assume it is
	// set.
	Vantage domain.Vantage

	// Incomplete reports that svcdoctor's own execution budget stopped the
	// measurement short. It says nothing about the target: an incomplete run is
	// a statement about svcdoctor, and a rule must never read it as evidence of
	// a failure.
	Incomplete bool
}
