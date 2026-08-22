// Package kafka holds the diagnosis rules that read Kafka evidence.
//
// A rule here is a pure function of a frozen domain.Graph, exactly like every
// other rule: the package is Kafka-specific because of what it reads and what it
// claims, not because the engine treats it differently. The engine never branches
// on a service name (ADR 0009), and a service rule is simply a rule that is only
// wired in for that service.
//
// It imports internal/domain and internal/service/kafka, and nothing else.
// depguard denies it the adapter, the probes, security, render and platform, and
// denies it net, crypto/tls, os and the random-number generators — the mechanism
// that makes "diagnosis performs no I/O" a build failure rather than a habit.
package kafka

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// CodeAdvertisedEndpointUnreachable is the flagship Kafka finding: the cluster
// answered, and then advertised an address this client cannot reach.
//
// The constant lives beside the rule that produces it rather than in a central
// catalogue, so that adding a service never edits shared core code
// (docs/FINDINGS.md section 1).
const CodeAdvertisedEndpointUnreachable domain.FindingCode = "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE"

// discriminator names the observation that would settle the hypothesis.
//
// It is a next observation and never a remediation: a discriminator says what
// would decide the open question, and the open question here is svcdoctor's own
// unfinished measurement. Fixed by ADR 0034 section 8.
const discriminator = "re-run with a larger execution budget so the unmeasured paths are attempted"

// AdvertisedEndpointUnreachable reports advertised broker endpoints that no
// measured path could reach from this vantage point.
//
// It is a diagnosis.Rule. The signature is not stated as one here because
// internal/diagnosis imports nothing from its own subpackages and this package
// must not import the engine to name its type; a caller wires it in with
// diagnosis.NewEngine(kafka.AdvertisedEndpointUnreachable), which compiles
// exactly because the function already has the contract's shape.
//
// # It anchors at the advertisement and walks down
//
// The rule enumerates kafka.broker_advertised nodes and, for each, walks
// Children to the sweep that advertisement caused. It never starts from a
// transport node and asks what that node is about, because that question is
// provenance and answering it from graph shape is what docs/REPORT_SCHEMA.md
// forbids and why Origin stays deferred. Anchoring supplies the context
// structurally: the rule is looking at these transport nodes because it walked
// here from this advertisement, and every claim it makes is local to that one
// fact. See ADR 0034 section 2.
//
// Consequently it scans no transport failure globally, reads no sweep scope,
// parses no evidence identifier, and matches no subject. Edges are enough.
//
// # One finding per unreachable advertisement, and no aggregate
//
// Three advertisements produce up to three findings, each naming its own broker
// and its own evidence. No cluster-level finding is produced: the obvious
// wording would be false, because the broker that answered Metadata was reached
// over a measured path in this very run. Two advertisements naming one endpoint
// are two facts and produce two findings; nothing deduplicates by endpoint or by
// node identifier. See ADR 0034 sections 10 and 12.
//
// # It owns the transport evidence beneath an advertisement
//
// No generic transport finding fires on the same nodes. This finding entails the
// transport observation and adds the broker identity, the advertisement that
// named the endpoint, and the contrast with a successful bootstrap; a generic
// one would add nothing the evidence node does not already state, which is the
// duplicate test ADR 0034 section 3 defines.
func AdvertisedEndpointUnreachable(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	// Graph.Nodes returns canonical order, so the findings are produced in a
	// deterministic order before the engine sorts them, and the rule's own
	// output does not depend on how the graph was assembled.
	for _, node := range g.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		finding, ok := evaluate(g, node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// verdict is what the evidence supports about one advertisement.
type verdict uint8

const (
	verdictNone verdict = iota
	verdictUnreachable
	verdictIncomplete
)

// evaluate applies ADR 0034 section 5 to one advertisement.
func evaluate(g domain.Graph, advertisement domain.Evidence) (domain.Finding, bool) {
	// An advertisement the cluster could not state usably is out of scope. It is
	// recorded as a FAIL node by Phase 3.3 and no sweep runs for it, and "the
	// cluster advertises an endpoint no client can act on" is a configuration
	// finding that deserves its own decision (ADR 0034 section 14).
	if advertisement.State() != domain.StatePass {
		return domain.Finding{}, false
	}

	exchange, ok := metadataExchange(g, advertisement)
	if !ok {
		return domain.Finding{}, false
	}

	s := collectSweep(g, advertisement.ID())
	if !s.wellFormed {
		return domain.Finding{}, false
	}

	terminalIsTLS := s.terminalIsTLS()
	if s.anyReachedTerminal(terminalIsTLS) {
		// A client that selects the working address succeeds, so the claim would
		// be false. No partial-reachability finding is emitted either: its
		// actionability depends on which address a real client would select,
		// which svcdoctor does not observe. The per-address evidence stays in the
		// graph and in the report. See ADR 0034 section 6.
		return domain.Finding{}, false
	}

	owners := s.owners(terminalIsTLS)
	failures := failedOwners(owners)
	if len(failures) == 0 {
		// Nothing was positively evidenced. "I could not measure it" and "it is
		// broken" are different claims (docs/FINDINGS.md section 4), and a
		// finding here would dress svcdoctor's own budget as the cluster's
		// fault. The summary already reports unknown and skipped counts.
		return domain.Finding{}, false
	}

	kind := verdictUnreachable
	if s.incomplete() {
		if !slices.ContainsFunc(owners, isIncomplete) {
			// The sweep is unresolved somewhere that is not any branch's
			// causal owner, so the hypothesis has nothing to cite for the
			// incompleteness it would assert, and the confirmed claim is
			// already blocked by that same incompleteness. Unreachable on a
			// graph the chain produces; withheld rather than guessed.
			return domain.Finding{}, false
		}
		kind = verdictIncomplete
	}

	return build(advertisement, exchange, owners, failures, s.reachabilityOf(), kind)
}

// metadataExchange returns the kafka.metadata node that carried the
// advertisement, when exactly one parent is that exchange and it passed.
//
// Both halves are required. The exchange passing is the contrast half of the
// claim and the reason it is about the cluster's configuration rather than about
// the network in general (ADR 0034 sections 5 and 11). Exactly one is required
// because the finding references "the" exchange, and an advertisement with two
// of them leaves no defensible answer to which one to cite.
func metadataExchange(g domain.Graph, advertisement domain.Evidence) (domain.Evidence, bool) {
	var found domain.Evidence
	count := 0
	for _, id := range g.Parents(advertisement.ID()) {
		parent, ok := g.Node(id)
		if !ok || parent.Step() != servicekafka.StepMetadata {
			continue
		}
		found = parent
		count++
	}
	if count != 1 || found.State() != domain.StatePass {
		return domain.Evidence{}, false
	}
	return found, true
}

// failedOwners returns the causal nodes that positively evidence a failure.
func failedOwners(owners []domain.Evidence) []domain.Evidence {
	var out []domain.Evidence
	for _, o := range owners {
		if o.State() == domain.StateFail {
			out = append(out, o)
		}
	}
	return out
}

// build assembles the finding.
//
// Every field is fixed by ADR 0034: the subject is the advertisement's own
// subject, the references are the exchange, the advertisement and the causal
// set, the vantage flag is unconditionally true, and the kind, severity and
// confidence follow the verdict.
func build(
	advertisement, exchange domain.Evidence,
	owners, failures []domain.Evidence,
	reach reachability,
	v verdict,
) (domain.Finding, bool) {
	broker := brokerPhrase(advertisement)
	earliest := earliestFailure(failures)
	outcome := reach.describe()

	in := domain.FindingInput{
		Code: CodeAdvertisedEndpointUnreachable,
		// The layer the claim concerns. Advertised-endpoint reachability is a
		// topology fact, and the advertisement this finding is anchored at is an
		// L6 node. It is not the earliest failing layer: that travels in the
		// summary, per docs/FINDINGS.md section 5, and the report derives
		// firstBrokenLayer from the graph rather than from findings.
		Layer: domain.LayerTopology,
		// The advertised endpoint, host:port as the cluster stated it, reused
		// from the advertisement rather than rebuilt. Never a resolved address:
		// the claim spans every path, and naming one would misrepresent its
		// scope (ADR 0034 section 12).
		Subject:      advertisement.Subject(),
		EvidenceRefs: references(advertisement, exchange, owners),
		// Reachability is a statement about network position. The same broker
		// may be reachable from inside the cluster and unreachable from a laptop
		// or a CI runner, and a reader who mistakes this for a claim about the
		// cluster has been actively misled. The flag is unconditional; the
		// Vantage itself stays on the report, recorded once (ADR 0034 section 17).
		VantageDependent: true,
		Recommendations:  recommendations(failures),
	}

	switch v {
	case verdictUnreachable:
		// The claim: no advertised path reaches this endpoint. That prevents
		// correct use of this broker — a client cannot produce to or consume
		// from the partitions it leads — which is what SeverityError means, and
		// it is ERROR whether one broker or three are affected. Severity is the
		// impact of the finding's own claim about its own subject, never a
		// count-derived cluster verdict (ADR 0034 section 13).
		in.Kind = domain.FindingKindConfirmed
		in.Severity = domain.SeverityError
		in.Confidence = domain.ConfidenceHigh
		in.Summary = fmt.Sprintf(
			"Kafka advertised endpoint%s could not be reached from this vantage point; "+
				"earliest evidenced failure %s", broker, earliest)
		in.Detail = fmt.Sprintf(
			"The Kafka Metadata exchange succeeded and advertised this endpoint, "+
				"and %s.\n"+
				"Reachability is relative to network position: this states what "+
				"this vantage point observed, not the health of the cluster.",
			outcome)
	case verdictIncomplete:
		// A different claim, and therefore a different severity: at least one
		// path failed and the rest were never attempted. That is a real problem
		// that is not currently breaking use, which is what SeverityWarn means.
		// The severity did not drop because belief is weaker — the claim changed
		// and the impact followed (ADR 0034 section 8).
		in.Kind = domain.FindingKindHypothesis
		in.Severity = domain.SeverityWarn
		in.Confidence = domain.ConfidenceLow
		in.Discriminator = discriminator
		in.Summary = fmt.Sprintf(
			"Kafka advertised endpoint%s may be unreachable from this vantage point; "+
				"at least one path failed with %s and the remaining paths were not measured",
			broker, earliest)
		in.Detail = fmt.Sprintf(
			"The Kafka Metadata exchange succeeded and advertised this endpoint, "+
				"and %s. At least one of those outcomes is a positively observed "+
				"failure and the rest were never finished, so unreachability is "+
				"not proven.\n"+
				"Reachability is relative to network position: this states what "+
				"this vantage point observed, not the health of the cluster.",
			outcome)
	case verdictNone:
		return domain.Finding{}, false
	}

	finding, err := domain.NewFinding(in)
	if err != nil {
		// Unreachable. Every value above is either a constant, a domain value
		// taken from a node the graph already validated, or text built from
		// layer and failure-class names, none of which can be blank or carry a
		// control character. TestEveryAuthorizedShapeBuildsAValidFinding drives
		// the whole matrix and fails if this branch is ever taken, so the
		// omission is proven not to happen rather than relied upon.
		return domain.Finding{}, false
	}
	return finding, true
}

// references assembles the evidence set: the successful half, the fact that
// named the endpoint, and the minimal causal set.
//
// Both halves of the contrast are required, because the finding's entire meaning
// is the contrast between them (docs/FINDINGS.md section 6). The causal set is
// each branch's earliest non-PASS node and nothing else — referencing every node
// of the sweep would bury the two or three that prove the claim. No PASS
// transport node appears: a failed TCP node exists only if the lookup produced
// addresses, and a failed TLS node only if the connection was established, so
// each causal node already carries its own precondition. See ADR 0034 section 11.
//
// domain.NewFinding deduplicates and sorts, so the result is byte-stable however
// the walk happened to collect it.
func references(advertisement, exchange domain.Evidence, owners []domain.Evidence) []domain.EvidenceID {
	out := make([]domain.EvidenceID, 0, len(owners)+2)
	out = append(out, exchange.ID(), advertisement.ID())
	for _, o := range owners {
		out = append(out, o.ID())
	}
	return out
}

// earliestFailure names the earliest evidenced failing layer and its classes.
//
// A TLS-only failure is still unreachability under a TLS plan, but
// TLS_HOSTNAME_MISMATCH is far more actionable than "unreachable", so the
// summary says where the failure was seen (ADR 0034 section 5, docs/FINDINGS.md
// section 5).
//
// When several addresses failed at that layer for different reasons, every
// distinct class is named, sorted, so the text is complete and does not depend on
// traversal order.
func earliestFailure(failures []domain.Evidence) string {
	layer := failures[0].Layer()
	for _, f := range failures {
		if f.Layer() < layer {
			layer = f.Layer()
		}
	}

	var classes []string
	for _, f := range failures {
		if f.Layer() != layer {
			continue
		}
		if name := f.FailureClass().String(); !slices.Contains(classes, name) {
			classes = append(classes, name)
		}
	}
	slices.Sort(classes)
	return layer.String() + " " + strings.Join(classes, ", ")
}

// brokerPhrase names the broker a finding is about, when the advertisement says.
//
// The node identifier travels in prose and on the referenced evidence, where it
// already is. It is not the subject: docs/REPORT_SCHEMA.md has no subject kind
// for a service-internal integer (ADR 0034 section 12). It is not identity in
// the redaction sense either — it names a position in a cluster rather than a
// host — so it survives a shareable report, and it is the only Kafka-specific
// value this prose carries. The advertised hostname is deliberately absent:
// the subject and the evidence references carry it, structurally, where
// redaction can transform it.
func brokerPhrase(advertisement domain.Evidence) string {
	id, ok := brokerNodeID(advertisement)
	if !ok {
		return ""
	}
	return " for broker node " + strconv.FormatInt(id, 10)
}

// brokerNodeID returns the node identifier an advertisement recorded, if it did.
//
// It is shared by the rules in this package rather than read twice. An
// advertisement without the attribute is not an error: the identifier decorates
// prose and is never a precondition of any claim, so a rule that cannot find one
// simply says less.
func brokerNodeID(advertisement domain.Evidence) (int64, bool) {
	value, ok := advertisement.Attribute(servicekafka.AttrBrokerNodeID)
	if !ok {
		return 0, false
	}
	return value.Int()
}
