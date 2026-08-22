package transport

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// CodeNameNotResolved reports a requested hostname that resolved to no usable
// address.
//
// # Why "not resolved" and not "does not exist"
//
// Because svcdoctor did not observe non-existence, and the layer below it went
// out of its way not to claim it either.
//
// The DNS probe emits DNS_NO_ADDRESS rather than DNS_NXDOMAIN for every negative
// answer, because Go's resolver sets the same not-found flag when a name does not
// exist and when it exists with no address record. DNS_NXDOMAIN is reserved for a
// resolver that reports non-existence distinctly, and nothing in this repository
// produces one. A finding that said "does not exist" would therefore be asserting
// a distinction its own evidence deliberately refused to draw.
//
// "Not resolved" is true in all three cases the class covers: a name that does
// not exist, a name with no address record, and a resolver that does not tell
// them apart.
const CodeNameNotResolved domain.FindingCode = "DNS_NAME_NOT_RESOLVED"

// CodeResolutionFailed reports a lookup that did not complete.
//
// It is the counterpart of CodeNameNotResolved and the two are never both true:
// one means the resolver answered and the answer was empty, the other that no
// answer arrived. They send a reader to different places — the zone and its
// records, or the resolver this host uses — which is why they are two codes and
// not one.
//
// The code says the resolution failed, not that the resolver is broken. A timeout
// and an unclassifiable resolver error prove that this lookup did not complete
// from here, and nothing about whose fault that is.
const CodeResolutionFailed domain.FindingCode = "DNS_RESOLUTION_FAILED"

// The recommendations. Each names something to inspect and asserts no cause.
const (
	recommendNameNotResolved = "Check that the hostname is spelled as intended and that it " +
		"has an address record visible to the resolver this host is configured to use"

	recommendResolutionFailed = "Check that the resolver this host is configured to use is " +
		"reachable and answering from this network position"
)

// The summaries. One stable sentence each, and neither varies by subcase.
const (
	summaryNameNotResolved = "The requested hostname did not resolve to a usable address " +
		"from this vantage point"

	summaryResolutionFailed = "Name resolution for the requested hostname did not complete " +
		"from this vantage point"
)

// The details. Both spend their length on what the finding does *not* say,
// because that is what a reader is most likely to supply for themselves.
const (
	detailNameNotResolved = "The resolver answered, and the answer contained no address this " +
		"client could use.\n" +
		"This does not establish that the hostname is unknown: the same answer is returned " +
		"for a name that has no address record, and many resolvers do not distinguish the " +
		"two. It also says nothing about whether the service behind the name is running.\n" +
		"Resolution depends on which resolver this host uses, so a different vantage point " +
		"may resolve the same name."

	detailResolutionFailed = "The lookup did not complete: the resolver either did not " +
		"answer in time or reported a failure svcdoctor could not classify further. The " +
		"exact outcome is recorded on the referenced evidence.\n" +
		"Nothing was learned about the hostname itself, and nothing here identifies what " +
		"prevented the answer.\n" +
		"Resolution depends on which resolver this host uses, so a different vantage point " +
		"may succeed."
)

// DNS diagnoses the name resolution of every requested target.
//
// It is a diagnosis.Rule. It enumerates requested-target anchors and reads the
// single DNS node directly beneath each — never a lookup found by scanning the
// graph for failures, which would be the unanchored rule ADR 0017 declined and
// which cannot tell an operator's target from a discovered one.
//
// # At most one finding per target
//
// The two codes rest on disjoint failure classes of one node, so they are
// mutually exclusive by construction rather than by arbitration. No suppression
// exists and none is needed.
//
// # What it withholds
//
//   - a PASS lookup, which is not a failure;
//   - an UNKNOWN lookup, which is svcdoctor's budget or a cancellation and never
//     a statement about the target;
//   - a SKIPPED lookup, which records that nothing was attempted;
//   - a FAIL lookup carrying any class outside the two authorized sets, which
//     would mean the node records something this rule has not been told how to
//     read.
//
// The last is deliberately a closed vocabulary. DNS_NXDOMAIN falls into it: the
// class exists, has no producer, and gets no mapping here — dead code for an
// unreachable case would be a claim waiting for someone to enable it.
func DNS(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	for _, s := range collectSweeps(g) {
		finding, ok := evaluateDNS(s)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateDNS decides what one sweep's lookup supports.
func evaluateDNS(s sweep) (domain.Finding, bool) {
	if !s.wellFormed || !s.hasLookup() {
		return domain.Finding{}, false
	}

	// FAIL is the producer's positive record that resolution did not deliver.
	// Every other state is either success or an absence of measurement, and a
	// rule that read one as failure would be manufacturing the claim its own
	// layer exists to avoid.
	if s.lookup.State() != domain.StateFail {
		return domain.Finding{}, false
	}

	var (
		code           domain.FindingCode
		summary        string
		detail         string
		recommendation string
	)
	switch s.lookup.FailureClass() {
	case domain.FailureDNSNoAddress:
		code, summary, detail = CodeNameNotResolved, summaryNameNotResolved, detailNameNotResolved
		recommendation = recommendNameNotResolved
	case domain.FailureDNSTimeout, domain.FailureDNSResolverFailure:
		code, summary, detail = CodeResolutionFailed, summaryResolutionFailed, detailResolutionFailed
		recommendation = recommendResolutionFailed
	default:
		// Includes DNS_NXDOMAIN, which no producer emits, and every class from
		// another layer's vocabulary. Withholding is the only honest response to
		// a node whose meaning this rule was not given.
		return domain.Finding{}, false
	}

	return build(buildInput{
		code:    code,
		layer:   domain.LayerDNS,
		subject: s.anchor.Subject(),
		// The lookup node alone. It is the whole proof: it records the failure
		// and the class the claim rests on. The anchor is not cited — it proves
		// the run's input rather than the failure, and it is already the
		// finding's subject.
		refs:           []domain.EvidenceID{s.lookup.ID()},
		summary:        summary,
		detail:         detail,
		recommendation: recommendation,
	})
}
