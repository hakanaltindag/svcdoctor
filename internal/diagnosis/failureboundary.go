package diagnosis

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// CodeFailureBoundary states where observation of one subject stopped
// succeeding.
//
// It is the first member of the `DIAG_` namespace: a generic code, produced by
// generic machinery over any service's graph, alongside the existing `DNS_`,
// `TCP_` and `TLS_` ones. It moves the frozen finding-code count 60 → 61, which
// ADR 0078 section 3 authorized for "the phase that implements it" and no
// earlier.
//
// # What it claims, exactly
//
// Along one measured branch, this is the transition between the deepest stage
// that positively succeeded and the shallowest that positively failed. Both
// halves are read from the graph and neither is inferred.
//
// # What it does not claim
//
// It is **not a cause**. "The failure is at TLS for this endpoint" is a contrast
// between two measured facts; "TLS configuration caused the incident" is a
// hypothesis, and this rule produces none. Nor does it claim anything about
// stages below the boundary: a step that did not run is neither healthy nor
// broken, and reading a blocked step as a second failure is the mistake
// docs/FINDINGS.md section 5 already forbids and ADR 0079 generalizes.
//
// It is INFO because it describes *where*, not *how bad*. The impact belongs to
// whichever finding reports the failure itself, and severity is never a proxy
// for anything else (docs/FINDINGS.md section 3.1 rule 5). A consumer that does
// not know this code sees one more INFO finding, which docs/CI.md's exit
// contract already tolerates: INFO never affects an exit code.
const CodeFailureBoundary domain.FindingCode = "DIAG_FAILURE_BOUNDARY"

// The prose, held as constants so that no part of it can come from anywhere
// else.
//
// Only two values are ever interpolated, and both are svcdoctor's own closed
// vocabulary: domain.Layer.Label(), which yields "dns", "tcp", "tls",
// "protocol", "auth" or "topology". Nothing a peer chose reaches any of these
// strings (ADR 0081 section 2.7).
const (
	summaryBoundaryContrast = "Observation of this subject last succeeded at the %s stage " +
		"and first failed at the %s stage"

	summaryBoundaryFirstStage = "The first stage measured for this subject, %s, failed"

	detailBoundaryMeaning = "This states where observation stopped succeeding and nothing " +
		"about why. It does not claim that this stage caused the failure, and it is not a " +
		"statement about any other stage."

	detailBoundaryNoLastGood = "\nNothing for this subject succeeded before it, so there is no " +
		"confirmed-good stage to contrast it against; the absence is reported rather than " +
		"filled in."

	// "neither proven to work nor proven to fail" rather than the shorter
	// "neither healthy nor broken": internal/cli's wording guard bans "healthy"
	// outright, negated or not, because SummaryStatus already refuses that claim
	// four levels down. The guard caught this string on the day it was written.
	detailBoundaryNotMeasured = "\nSome stages for this subject were not measured. A stage that " +
		"did not run was neither proven to work nor proven to fail, and none of them is " +
		"cited here."
)

// FailureBoundary reports, per subject, where observation stopped succeeding.
//
// # Why this is a rule and a finding
//
// ADR 0079 section 2.1 weighed four representations and Phase 10.1b re-weighed
// them against the implementation before activating this one. A field on
// domain.Report was rejected because the report assembles and validates rather
// than concludes (ADR 0015). A Graph query was rejected because whoever calls it
// decides what it means, and the obvious caller is a renderer. Computing it in
// the renderer was rejected twice over: it is reasoning, which ADR 0077 section
// 2.7 forbids, and two renderers would then hold two implementations of one
// conclusion that could disagree.
//
// A finding gets all of it for free: it is in canonical JSON, it cites its
// evidence, the report validates that those references resolve (ADR 0014),
// redaction already transforms its subject, every renderer already prints it,
// and convergence already knows what two of them mean.
//
// # One per subject, never one per run
//
// A run with a healthy bootstrap and one unreachable discovered endpoint has two
// boundaries. Merging them would produce "the service is unreachable", which is
// false of both. Identity is (Code, Subject), so two boundaries about two
// subjects are two findings and can never collapse into one.
//
// # Why it is CONFIRMED at HIGH
//
// ADR 0081 section 2.3 admits HIGH on direct authority — the peer stated it — or
// on complete contrast. This is neither, and is stronger than both: the boundary
// restates two states svcdoctor itself recorded, so it is true by construction
// from the evidence it cites. It infers nothing, which is also why it is
// CONFIRMED and why it carries no discriminator: there is no open question for
// one to settle, and domain.NewFinding refuses a CONFIRMED finding that pretends
// otherwise.
//
// # Incomplete runs
//
// It emits the same finding whether or not svcdoctor's own budget cut the run
// short, because the claim contains no statement about completeness: it names
// two measured nodes and says what they are. What an incomplete run changes is
// that more stages are unmeasured, and the detail says that a stage which did
// not run is neither healthy nor broken. A rule that *did* need completeness —
// one counting siblings, say — would have to consult RuleContext.Incomplete, and
// this one has nothing to consult it about.
func FailureBoundary(ctx RuleContext) []domain.Finding {
	boundaries := Boundaries(ctx.Graph)
	if len(boundaries) == 0 {
		return nil
	}

	out := make([]domain.Finding, 0, len(boundaries))
	for _, b := range boundaries {
		if f, ok := boundaryFinding(ctx.Graph, b); ok {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// boundaryFinding builds the finding for one boundary.
//
// It returns false rather than an error for a boundary it cannot express. The
// only way that happens is a graph whose failing node vanished between the walk
// and the lookup, which cannot occur on a frozen graph; returning false keeps a
// future change from turning an impossible state into a panic inside a rule.
func boundaryFinding(g domain.Graph, b Boundary) (domain.Finding, bool) {
	failing, ok := g.Node(b.FirstEvidencedFailure())
	if !ok {
		return domain.Finding{}, false
	}

	refs := []domain.EvidenceID{failing.ID()}
	detail := detailBoundaryMeaning
	summary := fmt.Sprintf(summaryBoundaryFirstStage, failing.Layer().Label())

	if lastGood, present := b.LastConfirmedGood(); present {
		good, found := g.Node(lastGood)
		if !found {
			return domain.Finding{}, false
		}
		refs = append(refs, good.ID())
		summary = fmt.Sprintf(summaryBoundaryContrast, good.Layer().Label(), failing.Layer().Label())
	} else {
		detail += detailBoundaryNoLastGood
	}

	if len(b.NotMeasured()) > 0 {
		detail += detailBoundaryNotMeasured
	}

	f, err := domain.NewFinding(domain.FindingInput{
		Code:       CodeFailureBoundary,
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityInfo,
		Confidence: domain.ConfidenceHigh,
		// The layer of the first evidenced failure (ADR 0079 section 2.3). It is
		// the failing half's own, never the confirmed-good one's: the boundary is
		// filed where observation stopped, not where it last worked.
		Layer:   failing.Layer(),
		Subject: b.Subject(),
		Summary: summary,
		Detail:  detail,
		// Both halves of a contrast are part of the proof: neither alone
		// establishes a boundary (docs/FINDINGS.md section 3.1 rule 10).
		EvidenceRefs: refs,
		// A reachability claim is a claim about a network position (ADR 0012),
		// and the transport layers are where reachability is what failed.
		VantageDependent: vantageDependentLayer(failing.Layer()),
	})
	if err != nil {
		return domain.Finding{}, false
	}
	return f, true
}

// vantageDependentLayer reports whether a failure at this layer is a claim about
// where svcdoctor ran from.
//
// ADR 0079 section 2.3 names the three. DNS, TCP and TLS all answer differently
// from a different network position — a name resolves elsewhere, a route exists
// elsewhere, a certificate is presented for a name reached differently. A
// protocol, authentication or topology failure is the peer's answer and does not
// change with the asker's position in the same way.
func vantageDependentLayer(l domain.Layer) bool {
	switch l {
	case domain.LayerDNS, domain.LayerTCP, domain.LayerTLS:
		return true
	case domain.LayerUnspecified, domain.LayerInput, domain.LayerProtocol,
		domain.LayerAuth, domain.LayerTopology:
		return false
	}
	return false
}
