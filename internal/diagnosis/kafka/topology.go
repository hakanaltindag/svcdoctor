package kafka

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The two topology-scoped Kafka claims, added in Phase 10.2 and frozen by
// ADR 0084.
//
// # What was already here, and why these are not it
//
// `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` answers *"was this one advertised
// endpoint reachable"*, once per advertisement, and has since Phase 3.6. ADR
// 0034 section 10 deliberately refused an aggregate on top of it, on the grounds
// that *"all three are unreachable" is the conjunction of three findings that
// are all present* — each naming its own broker and its own evidence.
//
// That reasoning was right about the conjunction and incomplete about what a
// reader needs. Two facts are **not** in the conjunction, and neither can be
// recovered from it:
//
//   - **whether the set was complete.** Three unreachable brokers beside a
//     fourth svcdoctor never attempted look exactly like three out of three.
//     The conjunction is three findings either way.
//   - **the contrast.** "One of three failed and the other two were reached"
//     rules against a client that has no path to the cluster at all; three
//     separate per-endpoint findings state it nowhere.
//
// ADR 0084 reopens section 10 for exactly those two, and upholds everything else
// it refused. What stays refused is listed on CodeAdvertisedTopologyUnsuitable.
const (
	// CodeAdvertisedTopologyReachability states the measured scope of
	// advertised-endpoint reachability for one Metadata response.
	//
	// **It is an observation, not a verdict.** It counts three categories —
	// reached, not reached, not measured — and says which. It attributes no
	// cause, ranks nothing, applies no threshold, and never says a cluster is
	// anything.
	//
	// It is INFO for the reason ADR 0034 section 13 gives and Phase 10.2 had to
	// re-apply: severity is the impact of this finding's own claim about its own
	// subject, and is *never a count-derived cluster verdict*. Escalating on how
	// many endpoints failed is precisely that verdict. The impact of an
	// unreachable broker endpoint is already carried, at ERROR, by
	// CodeAdvertisedEndpointUnreachable — one finding per endpoint, as before.
	CodeAdvertisedTopologyReachability domain.FindingCode = "KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY"

	// CodeAdvertisedTopologyUnsuitable is the hypothesis, and it is the one the
	// whole phase is careful about.
	//
	// **The claim is about suitability for a network position, never about a
	// configuration value.** svcdoctor reads no broker configuration and holds
	// no setting; what it has is a Metadata response and a set of transport
	// results. "The cluster advertised addresses this client cannot use" is
	// supported by the contrast between a reached bootstrap endpoint and an
	// advertised set none of which was reached. "advertised.listeners is
	// misconfigured" is a different sentence about a value nobody observed, and
	// this rule may not say it (ADR 0084 section 6).
	//
	// It is a HYPOTHESIS at MEDIUM and it **cannot** be HIGH: it declares
	// diagnosis.AuthorityNone, and the ladder admits HIGH only on direct peer
	// authority or complete contrast, neither of which a routing, listener or
	// broker-outage alternative allows svcdoctor to claim (ADR 0081 section 2.3).
	// TestTheSuitabilityHypothesisCanNeverBeHigh asserts it on the type rather
	// than on the sentence.
	//
	// # Distinguished from CodeAdvertisedEndpointUnusable by vantage
	//
	// The two names are close and the claims are opposite in exactly one field.
	// UNUSABLE is `vantageDependent: false`: the cluster reported a host and
	// port no client anywhere could act on, so every reader gets the same
	// broken pair. This is `vantageDependent: true`: the pair is well formed and
	// may serve some clients perfectly, and what is in question is whether it
	// serves one on *this* network. ADR 0035 drew that same contrast between
	// UNUSABLE and UNREACHABLE; this reuses it rather than inventing a second.
	//
	// # What stays refused, from ADR 0034 section 10 and ADR 0084 section 7
	//
	// `KAFKA_CLUSTER_UNHEALTHY`, `KAFKA_BROKER_DOWN` and `KAFKA_NETWORK_BROKEN`
	// remain unauthorized. So does a per-endpoint suitability claim: when peers
	// were reached, the advertised addresses demonstrably work for this client,
	// which contradicts the hypothesis rather than narrowing it to one broker.
	CodeAdvertisedTopologyUnsuitable domain.FindingCode = "KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE"
)

// The prose, held as constants so no part of it can come from anywhere else.
//
// **Nothing a peer chose is interpolated into any of it.** The only values that
// reach these strings are integers this package counted off the graph's own
// structure. An advertised hostname, an advertised port and a broker node
// identifier all travel on the subject and on the referenced evidence, where
// redaction transforms them (ADR 0081 section 2.7, docs/FINDINGS.md section 3.1
// rule 15).
const (
	summaryTopologyNoneReached = "None of the %d broker endpoints this cluster advertised " +
		"could be reached from this vantage point"

	summaryTopologyOnlyOne = "The one broker endpoint this cluster advertised could not be " +
		"reached from this vantage point"

	summaryTopologySomeReached = "%d of the %d broker endpoints this cluster advertised could " +
		"not be reached from this vantage point; the other %d %s reached"

	summaryTopologyIncomplete = "%d of the %d broker endpoints this cluster advertised could " +
		"not be reached from this vantage point; %d %s reached and %d %s not measured"

	detailTopologyMeaning = "This counts what was measured about the endpoints one Metadata " +
		"response advertised. It attributes no cause, and it states nothing about why any " +
		"endpoint answered as it did.\n" +
		"Reachability is relative to network position: this states what this vantage point " +
		"observed, not the health of the cluster."

	detailTopologyComplete = "\nEach endpoint that response advertised was measured for " +
		"reachability, so the counts above account for the whole advertised set."

	detailTopologyIncomplete = "\nSome advertised endpoints were not measured for " +
		"reachability, so nothing is claimed about them and no count here is a total. An " +
		"endpoint that was not measured is not an endpoint that refused."

	summaryUnsuitable = "The broker endpoints this cluster advertised may not be usable from " +
		"this client's network position"

	detailUnsuitable = "The bootstrap endpoint was reached and the Metadata exchange " +
		"completed there, and none of the %d broker endpoints that response advertised " +
		"could be reached from this vantage point. That contrast is consistent with a " +
		"cluster advertising addresses this client cannot use, and it is equally consistent " +
		"with the path to those addresses being unavailable for some other reason, so it is " +
		"not proven and no alternative has been excluded.\n" +
		"svcdoctor read no broker setting and holds none: the endpoints counted here are " +
		"the ones the Metadata response reported, and nothing here describes how the " +
		"cluster arrived at them.\n" +
		"Reachability is relative to network position: this states what this vantage point " +
		"observed, not the health of the cluster."

	// discriminatorUnsuitable names the observation that would settle it.
	//
	// It is an observation and never a remediation, and it is deliberately not
	// "measure it again": re-running the same sweep from the same position
	// produces the same evidence and separates nothing. What separates the
	// explanations is a comparison against the addresses this network is
	// expected to use, which svcdoctor cannot make on its own.
	discriminatorUnsuitable = "whether the advertised addresses are the ones a client on " +
		"this network is expected to use to reach these brokers"

	// recommendUnsuitable is the structured form of the same thought.
	//
	// It is built through diagnosis.NewAdvice as NEXT_EVIDENCE / COMPARE, so the
	// safety guardrails run over it, and only its action text reaches the report
	// — domain.Recommendation carries no class yet, and Phase 10.2 adds no
	// field for one (ADR 0084 section 9).
	recommendUnsuitable = "Compare the addresses this cluster advertised with the addresses " +
		"a client on this network is expected to use to reach its brokers"

	rationaleUnsuitable = "The bootstrap endpoint was reachable and the advertised endpoints " +
		"were not, so the two differ in something this client can observe only by comparison; " +
		"a match points away from the advertisement and towards the path, and a mismatch " +
		"points the other way."

	// recommendUnmeasured is the one piece of advice the observation carries,
	// and only when something was left unmeasured.
	//
	// It is self-collectable in the sense ADR 0082 section 2.4 defines: a
	// differently configured run could take it. Diagnosis still collects
	// nothing.
	recommendUnmeasured = "Re-run with a larger execution budget so the advertised endpoints " +
		"that were not measured are attempted"

	rationaleUnmeasured = "The counts above are partial while any advertised endpoint is " +
		"unmeasured, and a complete set is what separates \"this one endpoint failed\" from " +
		"\"the advertised set failed\"."
)

// reachVerdict is what a run learned about one advertised endpoint.
//
// Three, never two. A subject that was never attempted is not a subject that
// failed, and collapsing the third category is how "the advertised set is
// unreachable" gets said about endpoints nobody tried.
type reachVerdict uint8

const (
	// reachNotReached is a positively observed negative: every selectable path
	// was tried and none completed the transport the run required.
	//
	// An advertisement the cluster could not state usably is one of these. There
	// was no endpoint to sweep and none was promised, so the negative is
	// complete on the advertisement node alone; CodeAdvertisedEndpointUnusable
	// owns what it means.
	reachNotReached reachVerdict = iota

	// reachReached is a positively observed positive: one path completed.
	reachReached

	// reachNotMeasured is neither, and it is never merged into reachNotReached.
	reachNotMeasured
)

// AdvertisedTopologyReachability reports the measured scope of advertised
// endpoint reachability, per Metadata exchange.
//
// It is a diagnosis.Rule. The signature is not stated as one for the reason
// AdvertisedEndpointUnreachable gives: this package must not import the engine's
// type to name it.
//
// # It fires only when something positively failed
//
// A run in which every advertised endpoint was reached emits nothing. There is
// no "all good" finding, because a report that says what worked as well as what
// did not is a report nobody reads to the end, and the terminal already prints
// the topology counts for a healthy run.
//
// # It is CONFIRMED because it restates measured states
//
// Like DIAG_FAILURE_BOUNDARY, and for the same reason: every number in it is a
// count of nodes the graph already holds, so it is true by construction from the
// evidence it cites and infers nothing. That is also why it carries no
// discriminator — domain.NewFinding refuses one on a CONFIRMED finding, and
// there is no open question for one to settle.
func AdvertisedTopologyReachability(ctx diagnosis.RuleContext) []domain.Finding {
	var out []domain.Finding
	for _, t := range topologies(ctx) {
		if len(t.notReached) == 0 {
			continue
		}
		if f, ok := t.reachabilityFinding(); ok {
			out = append(out, f)
		}
	}
	return out
}

// AdvertisedTopologyUnsuitable reports that a cluster's advertised endpoints may
// not be usable from this client's network position.
//
// # The four conditions, and why each is load-bearing
//
//  1. **The Metadata exchange passed.** Without it there is no advertised set,
//     and a run stopped at authentication has no topology evidence at all
//     (ADR 0084 section 5).
//  2. **Every advertised endpoint was measured**, and svcdoctor's own budget did
//     not cut the run short. A partial set cannot support a claim about the set.
//  3. **At least one advertised endpoint positively failed.** An unmeasured set
//     is not a failed one.
//  4. **No advertised endpoint was reached.** This is the contradiction test,
//     and it is the reason no per-endpoint version of this hypothesis exists: a
//     reachable peer proves the advertised addresses do work from here, which is
//     evidence *against* the claim rather than a reason to narrow it to one
//     broker (ADR 0081 section 2.4, ADR 0084 section 7).
//
// The bootstrap contrast is what makes the hypothesis discriminable enough to
// emit at all. Without it — a client that reached nothing — every explanation
// looks the same and ADR 0083 section 2.2 rule 2 says to emit no causal
// hypothesis. Here the client demonstrably reached this cluster one way and
// could not reach it the way the cluster described, which excludes "this client
// has no path to the cluster" and excludes nothing else. One exclusion is
// MEDIUM; it is not HIGH, and the ladder makes that structural rather than
// stylistic.
func AdvertisedTopologyUnsuitable(ctx diagnosis.RuleContext) []domain.Finding {
	var out []domain.Finding
	for _, t := range topologies(ctx) {
		if !t.complete || len(t.reached) > 0 || len(t.notReached) == 0 {
			continue
		}
		if f, ok := t.suitabilityFinding(); ok {
			out = append(out, f)
		}
	}
	return out
}

// advertisedTopology is one Metadata response and what became of what it named.
type advertisedTopology struct {
	graph    domain.Graph
	exchange domain.Evidence

	reached     []domain.Evidence
	notReached  []domain.Evidence
	notMeasured []domain.Evidence

	// complete reports that every advertised endpoint has a positive verdict and
	// that svcdoctor's own budget did not stop the run.
	//
	// Both halves are required and neither implies the other. RuleContext.
	// Incomplete is svcdoctor's statement about its own execution (ADR 0080
	// section 2.1); the empty notMeasured set is a statement about this
	// exchange's own children. A run cancelled after the last sweep finished has
	// the second without the first.
	complete bool
}

// topologies reads every Metadata exchange the graph holds and classifies what
// it advertised.
//
// # At most one result per subject, by construction
//
// Two findings sharing a code and a subject would be merged by the engine, and
// the merge takes Summary and Detail from a RuleID tie-break (ADR 0081 section
// 2.2). For these codes that would be unsafe rather than merely arbitrary: "none
// of the 3" and "1 of the 3" are different sentences about different counts, and
// choosing between them alphabetically would publish a number nobody measured.
//
// So the shape that could produce it is refused instead of reconciled. A Kafka
// BASIC run performs exactly one Metadata exchange, and the exchange's evidence
// identifier carries the address it ran over, so two exchanges sharing one
// subject is a graph no producer makes. When one appears, this returns nothing
// for that subject — the same direction collectSweep errs in for a shape it does
// not recognize, and the direction that withholds a claim rather than inventing
// one. See ADR 0084 section 8.
func topologies(ctx diagnosis.RuleContext) []advertisedTopology {
	g := ctx.Graph

	var exchanges []domain.Evidence
	bySubject := map[domain.Subject]int{}
	for _, node := range g.Nodes() {
		if node.Step() != servicekafka.StepMetadata || node.State() != domain.StatePass {
			continue
		}
		exchanges = append(exchanges, node)
		bySubject[node.Subject()]++
	}

	var out []advertisedTopology
	for _, exchange := range exchanges {
		if bySubject[exchange.Subject()] != 1 {
			continue
		}
		t := advertisedTopology{graph: g, exchange: exchange}
		for _, childID := range g.Children(exchange.ID()) {
			child, ok := g.Node(childID)
			if !ok || child.Step() != servicekafka.StepBrokerAdvertised {
				continue
			}
			switch classifyAdvertised(g, child) {
			case reachReached:
				t.reached = append(t.reached, child)
			case reachNotReached:
				t.notReached = append(t.notReached, child)
			case reachNotMeasured:
				t.notMeasured = append(t.notMeasured, child)
			}
		}
		if t.total() == 0 {
			continue
		}
		t.complete = len(t.notMeasured) == 0 && !ctx.Incomplete
		out = append(out, t)
	}
	return out
}

// total returns how many advertisements this exchange carried.
func (t advertisedTopology) total() int {
	return len(t.reached) + len(t.notReached) + len(t.notMeasured)
}

// classifyAdvertised decides one advertisement's reachability verdict.
//
// # It is ADR 0051's predicate, and the agreement is deliberate
//
// `internal/app` owns the same rule for run completeness and
// `internal/render/terminal` owns it for the topology count line. Neither can be
// imported here — depguard denies diagnosis both, for reasons that have nothing
// to do with this — so the third statement of it is here, matching the other two
// step for step, including the order of its tests.
//
// The agreement is proven rather than asserted: TestTheTopologyCountsMatchThe
// RenderedTopologyLine drives one graph through both and compares the numbers,
// so a divergence fails a build rather than producing a report whose finding and
// whose summary line disagree.
//
// PASS is existential and FAIL is universal. One working path resolves an
// advertisement outright, whatever happened on its siblings; a negative is
// complete only when nothing was left unmeasured.
func classifyAdvertised(g domain.Graph, advertisement domain.Evidence) reachVerdict {
	if advertisement.State() != domain.StatePass {
		// The cluster named a host and port no client could act on. There was no
		// endpoint to sweep and none was promised, so this is a positively
		// observed negative rather than a gap in the measurement.
		return reachNotReached
	}

	s := collectSweep(g, advertisement.ID())
	if !s.wellFormed {
		// A shape the transport chain does not produce. The failure this
		// classification exists to prevent is a count asserting an endpoint was
		// unreachable when nobody looked, so an unrecognized shape errs towards
		// saying so.
		return reachNotMeasured
	}

	for _, lookup := range s.lookupFailures {
		if unknownLocal(lookup) {
			return reachNotMeasured
		}
	}
	for _, lookup := range s.lookupFailures {
		if lookup.State() == domain.StateFail {
			// Resolution produced nothing to connect to, which settles the
			// question on its own: there is no address a client could have
			// selected instead.
			return reachNotReached
		}
	}
	if len(s.paths) == 0 {
		// Either a name resolved and nothing was attempted against it, or there
		// was neither a lookup nor a connection. Both are shapes nobody
		// measured. An advertisement that named an address is not one of them:
		// it has no lookup and never will (ADR 0059), and it arrives here with
		// its connection nodes intact.
		return reachNotMeasured
	}

	terminalIsTLS := s.terminalIsTLS()
	if s.anyReachedTerminal(terminalIsTLS) {
		return reachReached
	}
	for _, p := range s.paths {
		if unknownLocal(p.tcp) {
			return reachNotMeasured
		}
		if p.hasTLS && unknownLocal(p.handshake) {
			return reachNotMeasured
		}
	}
	return reachNotReached
}

// unknownLocal reports whether a node records svcdoctor stopping rather than the
// target answering.
//
// # Why this is not isIncomplete
//
// isIncomplete answers a different question for a different rule, and it is
// wider: it also treats a SKIPPED node carrying a local class as unresolved,
// because ADR 0034 section 5 states the unreachability rule's condition over the
// whole sweep. Here the question is the one ADR 0051 asks — did the run learn
// whether this endpoint was reachable — and its answer deliberately excludes
// SKIPPED, because a SKIPPED node under a sweep restates a failure its blocker
// already owns.
//
// Using the wider predicate here would classify some positively observed
// negatives as unmeasured and make this rule's counts disagree with the topology
// line an operator reads three lines above them.
func unknownLocal(node domain.Evidence) bool {
	if node.State() != domain.StateUnknown {
		return false
	}
	switch node.FailureClass() {
	case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
		return true
	default:
		return false
	}
}

// reachabilityFinding builds the observation.
func (t advertisedTopology) reachabilityFinding() (domain.Finding, bool) {
	summary, detail := t.reachabilityProse()

	in := domain.FindingInput{
		Code: CodeAdvertisedTopologyReachability,
		Kind: domain.FindingKindConfirmed,
		// Never a count-derived escalation. See the note on the code.
		Severity:   domain.SeverityInfo,
		Confidence: domain.ConfidenceHigh,
		// Topology discovery. The claim is about what one Metadata response
		// advertised, which is an L6 fact, and not about the layer any
		// individual sweep failed at — those travel on the per-endpoint findings
		// and on the boundary.
		Layer: domain.LayerTopology,
		// The endpoint the question was asked at, taken from the exchange's own
		// subject. It is deliberately not an advertised endpoint: this claim is
		// about the set rather than about a member of it, and borrowing a
		// member's subject would put a set-level count under an endpoint-level
		// identity (ADR 0084 section 8).
		Subject:          t.exchange.Subject(),
		Summary:          summary,
		Detail:           detail,
		EvidenceRefs:     t.reachabilityRefs(),
		VantageDependent: true,
		Recommendations:  t.reachabilityRecommendations(),
	}

	finding, err := domain.NewFinding(in)
	if err != nil {
		// Unreachable. Every value is a constant, a domain value taken from a
		// node the graph already validated, or a decimal integer.
		// TestEveryTopologyShapeBuildsAValidFinding drives the matrix and fails
		// if this branch is ever taken.
		return domain.Finding{}, false
	}
	return finding, true
}

// reachabilityProse chooses the sentence the counts support.
//
// Three shapes, and the third exists because of the one claim this rule must
// never make. With anything unmeasured, "1 of 3 failed" would assert a total
// nobody established; the incomplete form states all three counts and calls none
// of them complete.
func (t advertisedTopology) reachabilityProse() (string, string) {
	detail := detailTopologyMeaning
	if !t.complete {
		return fmt.Sprintf(summaryTopologyIncomplete,
				len(t.notReached), t.total(),
				len(t.reached), were(len(t.reached)),
				len(t.notMeasured), were(len(t.notMeasured))),
			detail + detailTopologyIncomplete
	}
	detail += detailTopologyComplete
	if len(t.reached) == 0 {
		if t.total() == 1 {
			// "None of the 1 broker endpoints" is a sentence no one writes.
			return summaryTopologyOnlyOne, detail
		}
		return fmt.Sprintf(summaryTopologyNoneReached, t.total()), detail
	}
	return fmt.Sprintf(summaryTopologySomeReached,
		len(t.notReached), t.total(), len(t.reached), were(len(t.reached))), detail
}

// were agrees the verb with a count.
//
// Small, and it earns its place: these sentences carry three independent counts
// and any of them can be one. "1 were reached" in an operator-facing summary
// reads as a template that escaped, which is corrosive to a document whose whole
// value is that it was written carefully.
func were(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// reachabilityRefs is the minimal sufficient proof of the counts.
//
// Every reference is load-bearing, which is the test ADR 0078 section 2.3 rule 1
// states: delete any one of them from the graph and a count changes.
//
//   - the exchange, because it is what advertised the set and what makes this a
//     statement about a topology rather than about some endpoints;
//   - every advertisement node, because they are the set and its size;
//   - one reaching node per reached endpoint, because "these were reached" rests
//     on a measurement and not on the absence of a failure;
//   - the causal failure node of each unreached endpoint.
//
// An unmeasured endpoint contributes its advertisement and nothing else: there
// is no positive observation to cite, and citing the unmeasured node would put a
// state that proves nothing in a position that reads as proof.
func (t advertisedTopology) reachabilityRefs() []domain.EvidenceID {
	refs := []domain.EvidenceID{t.exchange.ID()}
	for _, group := range [][]domain.Evidence{t.reached, t.notReached, t.notMeasured} {
		for _, advertisement := range group {
			refs = append(refs, advertisement.ID())
		}
	}
	for _, advertisement := range t.reached {
		if node, ok := t.reachingNode(advertisement); ok {
			refs = append(refs, node.ID())
		}
	}
	refs = append(refs, t.failureRefs()...)
	return refs
}

// failureRefs returns the causal node of each unreached advertisement.
//
// An advertisement the cluster stated unusably has no sweep and contributes
// none: its own node is the whole of the evidence, and it is already cited.
func (t advertisedTopology) failureRefs() []domain.EvidenceID {
	var out []domain.EvidenceID
	for _, advertisement := range t.notReached {
		if advertisement.State() != domain.StatePass {
			continue
		}
		s := collectSweep(t.graph, advertisement.ID())
		if !s.wellFormed {
			continue
		}
		for _, owner := range failedOwners(s.owners(s.terminalIsTLS())) {
			out = append(out, owner.ID())
		}
	}
	return out
}

// reachingNode returns one node proving an advertised endpoint was reached.
//
// One is sufficient and more would be decoration: a client that selects a
// working address succeeds, so a single completed path establishes the whole of
// what "reached" claims.
func (t advertisedTopology) reachingNode(advertisement domain.Evidence) (domain.Evidence, bool) {
	s := collectSweep(t.graph, advertisement.ID())
	if !s.wellFormed {
		return domain.Evidence{}, false
	}
	terminalIsTLS := s.terminalIsTLS()
	for _, p := range s.paths {
		if !p.reachedTerminal(terminalIsTLS) {
			continue
		}
		if terminalIsTLS {
			return p.handshake, true
		}
		return p.tcp, true
	}
	return domain.Evidence{}, false
}

// reachabilityRecommendations returns the one piece of advice the observation
// can carry, and only when the counts are partial.
//
// A complete set needs no next observation from this finding: it states what was
// measured, the per-endpoint findings state the impact, and the boundary states
// where each one stopped.
func (t advertisedTopology) reachabilityRecommendations() []domain.Recommendation {
	if t.complete {
		return nil
	}
	return diagnosis.Recommend(diagnosis.AdviceInput{
		Kind:            diagnosis.AdviceKindNextEvidence,
		Safety:          diagnosis.SafetyObserve,
		Action:          recommendUnmeasured,
		Rationale:       rationaleUnmeasured,
		SelfCollectable: true,
	}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
}

// suitabilityFinding builds the hypothesis.
func (t advertisedTopology) suitabilityFinding() (domain.Finding, bool) {
	basis, err := t.suitabilityBasis()
	if err != nil {
		// A basis this rule cannot justify is a defect in the rule, and the
		// response is to say nothing rather than to say it weakly.
		return domain.Finding{}, false
	}

	// AuthorityNone is the whole ceiling, declared rather than assumed. Direct
	// authority would mean the peer stated the condition in its own protocol,
	// and no Kafka field says "my advertised address is unreachable from where
	// you are"; complete contrast would mean every distinguishable alternative
	// had been measured and excluded, and routing, listener exposure and a
	// broker-side outage are none of them measured here.
	confidence, err := diagnosis.AdmitConfidence(
		domain.FindingKindHypothesis, diagnosis.AuthorityNone, basis)
	if err != nil {
		return domain.Finding{}, false
	}

	in := domain.FindingInput{
		Code: CodeAdvertisedTopologyUnsuitable,
		Kind: domain.FindingKindHypothesis,
		// The same reading ADR 0034 section 8 gives its own hypothesis: a real
		// problem stated as a possibility, whose impact follows the claim rather
		// than the belief. The impact of the endpoints themselves is already
		// ERROR, once per endpoint.
		Severity:         domain.SeverityWarn,
		Confidence:       confidence,
		Layer:            domain.LayerTopology,
		Subject:          t.exchange.Subject(),
		Summary:          summaryUnsuitable,
		Detail:           fmt.Sprintf(detailUnsuitable, t.total()),
		EvidenceRefs:     basis.Supporting(),
		VantageDependent: true,
		Discriminator:    discriminatorUnsuitable,
		Recommendations: diagnosis.Recommend(diagnosis.AdviceInput{
			Kind:      diagnosis.AdviceKindNextEvidence,
			Safety:    diagnosis.SafetyCompare,
			Action:    recommendUnsuitable,
			Rationale: rationaleUnsuitable,
			// svcdoctor cannot take this observation in any run. It has no
			// model of what this network expects, and saying so is more useful
			// than implying it already looked (ADR 0082 section 2.4).
			SelfCollectable: false,
		}, domain.FindingKindHypothesis, confidence),
	}

	finding, err := domain.NewFinding(in)
	if err != nil {
		return domain.Finding{}, false
	}
	return finding, true
}

// suitabilityBasis assembles what the hypothesis rests on, with the four
// relations kept apart.
//
// It is built through diagnosis.BasisBuilder rather than as a plain slice so
// that the coherence checks run: every identifier resolves in the graph, no
// blocked node is cited in either direction, and the confidence ladder is
// applied to a basis rather than chosen by hand.
//
// Nothing is recorded as contradicting, and that is the shape of the rule rather
// than an omission: the one thing that would contradict this claim is a reached
// advertised endpoint, and its presence stops the rule from running at all.
func (t advertisedTopology) suitabilityBasis() (diagnosis.EvidenceBasis, error) {
	b := diagnosis.NewBasis().Support(t.exchange.ID())
	for _, advertisement := range t.notReached {
		b.Support(advertisement.ID())
	}
	b.Support(t.failureRefs()...)
	return b.Freeze(t.graph)
}
