package postgres

import (
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

const (
	summaryTLSDeclined = "The PostgreSQL endpoint declined the requested TLS upgrade"

	detailTLSDeclined = "svcdoctor sent an SSLRequest because this run required an encrypted " +
		"channel, and the endpoint answered that it would not encrypt this connection.\n" +
		"Nothing was sent afterwards and no credential was presented."

	recommendTLSDeclined = "Check whether this PostgreSQL endpoint is configured to accept " +
		"encrypted connections, and whether anything between this vantage point and it " +
		"answers the SSLRequest on its behalf"
)

// SSLRequest reports PostgreSQL endpoints that refused to encrypt a connection
// this run required to be encrypted.
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
// # What it does not fire on
//
// An `E`-shaped answer, a malformed reply and a peer close all leave this node
// FAIL with a different class, and none produces a finding in Phase 4.6. They
// are recorded as a gap in ADR 0040 section 26 rather than covered by widening
// this predicate: an `E` answer is a peer refusing to negotiate and deserves a
// claim, but no measurement of one exists and this package does not authorize
// findings for shapes nobody has seen.
//
// A SKIPPED node — the run asked for no TLS — is likewise not a finding. Nothing
// failed, and `postgres.tls.plan` on that node states why.
func SSLRequest(g domain.Graph) []domain.Finding {
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
