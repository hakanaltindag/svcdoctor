package postgres

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// CodeTLSDeclined reports an endpoint that answered PostgreSQL's in-band SSL
// negotiation by refusing to encrypt this connection.
//
// # Why "declined" attributes agency here, and the floors do not
//
// The predicate requires `postgres.ssl.offered` to be present and false, and the
// producer records that attribute **only when a real answer arrived**. So the
// endpoint positively said no, and saying it declined is reporting what
// happened. A floor finding has no such record and says only that an exchange
// did not complete.
const CodeTLSDeclined domain.FindingCode = "POSTGRES_TLS_DECLINED"

// CodeSSLNegotiationFailed is the L3 floor: the negotiation did not complete,
// and svcdoctor cannot say why.
//
// # Why a floor rather than three codes
//
// The three classes it covers — an answer that was not one of the two the
// protocol defines, a peer that closed, a reply that could not be decoded — pose
// one question, *is this the service I meant?*, and start one investigation. The
// class on the cited node distinguishes them for a machine.
//
// # Why it does not say "this is not PostgreSQL"
//
// Because the same bytes arrive from a PostgreSQL server behind something that
// rewrites them, and a peer that closes proves nothing about what it was. The
// most common real cause is a wrong port, which is why the recommendation asks
// about the endpoint rather than asserting it.
const CodeSSLNegotiationFailed domain.FindingCode = "POSTGRES_SSL_NEGOTIATION_FAILED"

const (
	summaryTLSDeclined = "The PostgreSQL endpoint declined the requested TLS upgrade"

	detailTLSDeclined = "svcdoctor sent an SSLRequest because this run required an encrypted " +
		"channel, and the endpoint answered that it would not encrypt this connection.\n" +
		"Nothing was sent afterwards and no credential was presented."

	recommendTLSDeclined = "Check whether this PostgreSQL endpoint is configured to accept " +
		"encrypted connections, and whether anything between this vantage point and it " +
		"answers the SSLRequest on its behalf"
)

const (
	summarySSLNegotiationFailed = "The PostgreSQL SSL negotiation did not complete at this " +
		"endpoint"

	detailSSLNegotiationFailed = "svcdoctor sent an SSLRequest because this run required an " +
		"encrypted channel, and the exchange did not complete. What arrived instead — an " +
		"answer the protocol does not define, a peer that closed, or a reply that could not " +
		"be decoded — is recorded on the referenced evidence.\n" +
		"This does not establish what is at this endpoint. A PostgreSQL server behind " +
		"something that rewrites its answers and a service that speaks another protocol " +
		"entirely can produce the same observation, and svcdoctor observed neither.\n" +
		"The exchange stopped here: nothing was encrypted, and nothing was presented to " +
		"this endpoint afterwards."

	recommendSSLNegotiationFailed = "Check that this endpoint is the PostgreSQL service this " +
		"run was meant to reach, and read the referenced evidence for what the exchange " +
		"observed"
)

// negotiationFloorClasses is the closed set the floor covers.
//
// PROTOCOL_UNSUPPORTED_CAPABILITY is deliberately absent: it is produced only on
// the branch that also records postgres.ssl.offered, so it always satisfies
// CodeTLSDeclined's predicate and the two rules are disjoint on class alone —
// with no ordering, no suppression and no attribute check here.
//
// Closed on purpose. A class added to the domain later produces no finding until
// somebody decides what it means, which is safer than a default branch handing it
// the floor's own "could not say why" wording.
var negotiationFloorClasses = map[domain.FailureClass]bool{
	domain.FailureProtocolUnexpectedResponse: true,
	domain.FailureProtocolPeerClosed:         true,
	domain.FailureProtocolMalformedResponse:  true,
}

// SSLRequest reports PostgreSQL endpoints that refused to encrypt a connection
// this run required to be encrypted, and endpoints whose negotiation did not
// complete at all.
//
// It is a diagnosis.Rule. The signature is not stated as one here because
// internal/diagnosis imports nothing from its own subpackages and this package
// must not import the engine to name its type; a caller wires it in with
// diagnosis.NewEngine(postgres.SSLRequest), which compiles exactly because the
// function already has the contract's shape.
//
// # It anchors at the negotiation and reads nothing else
//
// One node, one claim. It does not walk to the TLS node beneath — that node is
// SKIPPED and blocked by this one, and docs/FINDINGS.md section 3.1 item 11
// forbids citing a blocked step as a cause. It does not read the transport nodes
// above, because this claim is about what the endpoint answered rather than
// about how it was reached.
//
// # Two claims, disjoint on FailureClass
//
// An endpoint that answered `N` declined, and says so. An endpoint whose answer
// the protocol does not define, that closed, or whose reply could not be decoded
// produces the floor: something went wrong and svcdoctor cannot say what. ADR
// 0040 left the second set unowned because it had measured none of those shapes;
// ADR 0045 closes it, because an HTTP server on the port produces one and
// reported `status: OK`.
//
// # What it still does not fire on
//
// An `E`-shaped answer gets no claim of its own. It lands in the floor with the
// rest, and the reason is ADR 0040's unchanged: a peer refusing to negotiate
// deserves a distinct claim and that exact shape has still not been measured.
// The class on the cited node distinguishes it for a machine meanwhile.
//
// UNKNOWN — cancellation, an exhausted budget — is not a failure and produces
// nothing. A SKIPPED node, where the run asked for no TLS, is likewise not a
// finding: nothing failed, and `postgres.tls.plan` on that node states why.
func SSLRequest(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	// Graph.Nodes returns canonical order, so findings are produced in a
	// deterministic order before the engine sorts them, and the rule's own
	// output does not depend on how the graph was assembled.
	for _, node := range g.Nodes() {
		if node.Step() != servicepostgres.StepSSLRequest {
			continue
		}
		finding, ok := evaluateSSLRequest(node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateSSLRequest applies ADR 0040 section 7 to one negotiation node.
func evaluateSSLRequest(node domain.Evidence) (domain.Finding, bool) {
	if node.State() != domain.StateFail {
		return domain.Finding{}, false
	}
	if negotiationFloorClasses[node.FailureClass()] {
		return build(domain.FindingInput{
			Code: CodeSSLNegotiationFailed,
			Kind: domain.FindingKindConfirmed,
			// The run required an encrypted channel and this endpoint did not
			// deliver the exchange that precedes one, so nothing further could be
			// attempted on this connection. The same reading as the declined
			// finding beside it.
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerTLS,
			Subject:    node.Subject(),
			Summary:    summarySSLNegotiationFailed,
			Detail:     detailSSLNegotiationFailed,
			// **True, where the declined finding beside it is false**, and that
			// is derived rather than inconsistent. Whether an endpoint will
			// encrypt is a server-wide setting answered identically to every
			// source; a floor attributes nothing, so it cannot exclude a cause
			// keyed on where the connection came from.
			VantageDependent: true,
			// The node alone. Its SKIPPED handshake child is not cited: a
			// blocked step is never a cause, and this node is its blocker.
			EvidenceRefs:    []domain.EvidenceID{node.ID()},
			Recommendations: recommend(recommendSSLNegotiationFailed),
		})
	}

	if node.FailureClass() != domain.FailureProtocolUnsupportedCapability {
		return domain.Finding{}, false
	}

	// The attribute is required even though the class implies it. Its presence
	// is what separates "the endpoint said no" from "svcdoctor never found out",
	// and those are different claims of which only the first is this finding.
	offered, ok := boolAttr(node, servicepostgres.AttrSSLOffered)
	if !ok || offered {
		return domain.Finding{}, false
	}

	return build(domain.FindingInput{
		Code: CodeTLSDeclined,
		Kind: domain.FindingKindConfirmed,
		// The run required an encrypted channel and cannot have one here, so
		// nothing further could proceed on this connection. That prevents
		// correct use of this endpoint under this run's plan, which is what
		// SeverityError means.
		Severity:   domain.SeverityError,
		Confidence: domain.ConfidenceHigh,
		// The claim's layer is the anchor's own. The negotiation sits at L3
		// despite being PostgreSQL-specific: a layer says where in the ladder a
		// step sits, not what taxonomy its failure belongs to.
		Layer:   domain.LayerTLS,
		Subject: node.Subject(),
		Summary: summaryTLSDeclined,
		Detail:  detailTLSDeclined,
		// Whether an endpoint will encrypt is a server-wide setting on a
		// backend and an instance-wide one on a pooler; the same peer answers
		// every source identically. Marking this vantage-dependent would invite
		// a retry from elsewhere that cannot help.
		VantageDependent: false,
		EvidenceRefs:     []domain.EvidenceID{node.ID()},
		Recommendations:  recommend(recommendTLSDeclined),
	})
}
