package kafka

import (
	"strconv"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// CodeAdvertisedEndpointUnusable reports a broker advertisement that names
// nowhere a client could connect.
//
// # Why "unusable" and not "invalid" or "misconfigured"
//
// The code names what svcdoctor observed, which is the narrowest of the three.
//
//   - **Not "misconfigured".** A Metadata response says what host and port a
//     broker reports. It does not say how the broker arrived at them, and
//     svcdoctor never sees that: the values normally come from a listener
//     configuration, but a proxy, a service mesh or an operator's rewrite can
//     produce them just as well. Naming a cause svcdoctor did not observe would
//     be the guessed root cause docs/FINDINGS.md section 3.1 forbids.
//   - **Not "invalid".** Invalidity is a judgement against a specification, and
//     svcdoctor checked no specification. It checked whether the pair can be
//     turned into a network target, which is a smaller and fully evidenced
//     question.
//   - **"Unusable" is the producer's own vocabulary.** The adapter decides
//     usability and records the outcome as the node's state (ADR 0031); this
//     code names that determination and adds no second standard.
//
// It shares a prefix with CodeAdvertisedEndpointUnreachable deliberately. The
// two are adjacent claims about the same kind of subject and an operator meets
// them in the same place, so the namespace reads as a family rather than as two
// unrelated strings. They are never both true of one advertisement; see
// UnusableAdvertisement.
const CodeAdvertisedEndpointUnusable domain.FindingCode = "KAFKA_ADVERTISED_ENDPOINT_UNUSABLE"

// recommendUnusable names what to inspect without claiming what caused it.
//
// Both halves are real inspection targets and neither is asserted to be the
// source: svcdoctor observed the values in a Metadata response and nothing about
// where they were produced. No executable remediation, ever.
const recommendUnusable = "Check how this broker's advertised host and port are configured, " +
	"and whether anything rewrites Kafka Metadata responses between the broker and this client"

// UnusableAdvertisement reports broker advertisements that cannot be turned into
// a network endpoint at all.
//
// It is a diagnosis.Rule, wired in the same way as AdvertisedEndpointUnreachable
// and independent of it.
//
// # The claim, exactly
//
// *The cluster answered Metadata, and the host and port it reported for this
// broker do not name somewhere a client could connect.*
//
// That is a statement about the values that arrived, and about nothing else. It
// does not say the broker is down, that the cluster is misconfigured, or where
// the values came from — see CodeAdvertisedEndpointUnusable on why the code is
// worded the way it is.
//
// # Why this is a separate finding rather than a case of unreachability
//
// The two claims rest on disjoint evidence and neither entails the other:
//
//	UNUSABLE      no endpoint could be formed, so nothing was measured
//	UNREACHABLE   an endpoint was formed, transport ran, and nothing reached it
//
// They are also **mutually exclusive by construction**. Phase 3.3 records an
// advertisement as PASS exactly when it names a usable endpoint and FAIL exactly
// when it does not; AdvertisedEndpointUnreachable requires PASS and this rule
// requires FAIL, so one advertisement can never produce both. That is asserted
// rather than assumed — see the composition tests.
//
// The independence test in ADR 0034 section 3 is met from the other direction
// too: this finding would remain true and useful if reachability diagnosis did
// not exist, because it needs no transport evidence to prove anything.
//
// # Anchoring
//
// It enumerates kafka.broker_advertised nodes and reads each one, plus the
// exchange above it. It scans no protocol failures globally, walks no transport
// evidence, reads no sweep scope, parses no evidence identifier and infers no
// Origin. Unlike AdvertisedEndpointUnreachable it does not walk downward at all:
// the claim is about the advertisement itself, and there is nothing beneath it —
// Phase 3.4 correctly runs no sweep for an advertisement it cannot turn into a
// target (ADR 0033).
func UnusableAdvertisement(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	// Canonical order in, deterministic order out, before the engine sorts.
	for _, node := range g.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		finding, ok := evaluateUsability(g, node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateUsability decides whether one advertisement supports the claim.
func evaluateUsability(g domain.Graph, advertisement domain.Evidence) (domain.Finding, bool) {
	// FAIL is the producer's positive record that the advertised pair names
	// nowhere to connect. PASS means the opposite and belongs to the
	// reachability rule; any other state would be a shape Phase 3.3 does not
	// produce, and diagnosis does not guess at one.
	if advertisement.State() != domain.StateFail {
		return domain.Finding{}, false
	}

	// The class is checked as well as the state, because the two together are
	// what the producer commits to. A FAIL advertisement carrying some other
	// class — an execution class, say — would mean the node records something
	// this rule has not been told how to read, and inventing a reading is the
	// one thing a rule may not do.
	if advertisement.FailureClass() != domain.FailureProtocolUnexpectedResponse {
		return domain.Finding{}, false
	}

	// The exchange establishes that a broker actually reported this, rather than
	// the node having arrived some other way, and it is the half of the claim
	// that says the cluster answered at all. Requiring it and then not citing it
	// would leave a reader unable to check the rule's own precondition.
	exchange, ok := metadataExchange(g, advertisement)
	if !ok {
		return domain.Finding{}, false
	}

	// Deliberately no check that the advertisement has no transport children.
	// The claim is about the values that arrived and is fully evidenced by this
	// node; what any later phase might choose to measure alongside them cannot
	// make it false, and a rule that silently stopped firing when the graph grew
	// a node would be worse than one that ignores it.

	return buildUnusable(advertisement, exchange)
}

// buildUnusable assembles the finding.
func buildUnusable(advertisement, exchange domain.Evidence) (domain.Finding, bool) {
	in := domain.FindingInput{
		Code: CodeAdvertisedEndpointUnusable,
		// The evidence directly records the stated condition: the producer
		// determined that this pair names nowhere to connect, and this rule
		// claims exactly that. Nothing is left open, so there is no
		// discriminator and the model would reject one.
		Kind: domain.FindingKindConfirmed,
		// A broker whose advertised endpoint cannot be connected to prevents
		// correct use of that broker, for every client that reads this Metadata
		// response — which is what SeverityError means. It is per-subject impact,
		// exactly as ADR 0034 section 13 defines it, and not an inheritance from
		// the reachability finding.
		//
		// CRITICAL is not used: breadth would be a cluster-level claim, and the
		// cluster demonstrably answered.
		Severity: domain.SeverityError,
		// Direct and strongly matching evidence: the cited node is the
		// determination itself, not an indirect signal.
		Confidence: domain.ConfidenceHigh,
		// The layer of the claim, which is topology — the advertisement is an L6
		// fact and the finding is about that fact. Here it coincides with the
		// report's firstBrokenLayer, because the only FAIL node in a run like
		// this is the advertisement itself. In the reachability finding the two
		// differ. Both are correct; see docs/REPORT_SCHEMA.md section 7.5.
		Layer: domain.LayerTopology,
		// Reused from the advertisement, never rebuilt, and never repaired. The
		// producer renders what was advertised rather than what would work — a
		// missing host stays ":9093" and an impossible port stays
		// "broker:-1" — and a diagnosis that substituted a plausible endpoint
		// would be inventing the target the cluster failed to name.
		Subject:          advertisement.Subject(),
		EvidenceRefs:     []domain.EvidenceID{exchange.ID(), advertisement.ID()},
		Summary:          unusableSummary(advertisement),
		Detail:           unusableDetail,
		Recommendations:  unusableRecommendations(),
		VantageDependent: false,
	}

	finding, err := domain.NewFinding(in)
	if err != nil {
		// Unreachable: the subject comes from a node the graph validated, the
		// references come from that graph, and the prose is a constant plus a
		// decimal integer. TestEveryUnusableShapeBuildsAValidFinding drives the
		// whole producer matrix and fails if this branch is ever taken.
		return domain.Finding{}, false
	}
	return finding, true
}

// unusableSummary is one sentence, stable across every way an advertisement can
// be unusable.
//
// It deliberately does not say *how* the endpoint is unusable. The subject shows
// it at a glance — ":9093" has no host, "broker.internal:-1" has no usable port
// — and the exact values are structured attributes on the cited advertisement,
// where a machine reads them without parsing anything. Naming them here would
// duplicate structure in prose and would make the sentence vary across subcases
// that share one claim.
//
// The node identifier is the one specific it carries, and it earns its place:
// it is not on the subject, it is not identity in the redaction sense, and after
// pseudonymization it is the only thing distinguishing one broker's unusable
// advertisement from another's — two of which can redact to the same ":9093".
func unusableSummary(advertisement domain.Evidence) string {
	id, ok := brokerNodeID(advertisement)
	if !ok {
		return "Kafka advertised a broker without a usable network endpoint"
	}
	return "Kafka advertised broker node " + strconv.FormatInt(id, 10) +
		" without a usable network endpoint"
}

// unusableDetail explains the claim and its scope.
//
// It is a constant because the graph's structured evidence already distinguishes
// the subcases and prose must not duplicate it. The second sentence is the one
// that earns its place: it says in words why this finding is not
// vantage-dependent, which is the property most likely to be misread by someone
// who met the reachability finding first.
const unusableDetail = "The Kafka Metadata exchange succeeded, and the host and port it " +
	"reported for this broker do not name somewhere a client could connect. Both values are " +
	"recorded on the referenced advertisement exactly as they arrived.\n" +
	"This is a property of what the cluster reported rather than of this vantage point: any " +
	"client reading the same Metadata response receives the same endpoint."

// unusableRecommendations returns the single recommendation this claim supports.
func unusableRecommendations() []domain.Recommendation {
	recommendation, err := domain.NewRecommendation(recommendUnusable)
	if err != nil {
		// Unreachable: a non-empty, trimmed, control-character-free constant.
		// Pinned by TestUnusableRecommendationTextIsValid.
		return nil
	}
	return []domain.Recommendation{recommendation}
}
