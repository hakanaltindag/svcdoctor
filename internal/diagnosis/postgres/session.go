package postgres

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The codes the session step can produce.
const (
	// CodeDatabaseNotFound names the endpoint's own assertion.
	//
	// # The code and the prose differ in word strength, deliberately
	//
	// The code mirrors the peer's assertion, whose own error-code name is an
	// absent database, and mirrors the service-neutral RESOURCE_NOT_FOUND it is
	// produced from. The **prose** stays valid across all three conditions that
	// share that code — no catalog row, a row that disappeared mid-lookup, and a
	// catalog row whose files are missing — which is why it says "is not
	// available" and never "does not exist".
	//
	// Neither is to be "fixed" to match the other. A code and the text beside it
	// are different contracts (docs/FINDINGS.md section 2), and this is the case
	// that shows why: renaming the code weaker than the peer's own assertion
	// would be a different inaccuracy, not a smaller one.
	CodeDatabaseNotFound domain.FindingCode = "POSTGRES_DATABASE_NOT_FOUND"

	// CodeDatabaseConnectDenied is as narrow as the evidence.
	//
	// Of the endpoint's three insufficient-privilege sites in this window, only
	// the CONNECT check is reachable for svcdoctor: the other two need a startup
	// option it does not send. No other privilege check can have run, because
	// svcdoctor issues no statement (ADR 0039 section 9).
	CodeDatabaseConnectDenied domain.FindingCode = "POSTGRES_DATABASE_CONNECT_DENIED"

	// CodeSessionEstablishmentFailed is the L5 session floor.
	//
	// It is where a connection-limit refusal lands, and it does **not** become
	// "the endpoint is out of connections": that is what the message says and
	// not what the evidence contract proves, and a pooler reports its own client
	// limit with a different code entirely. ADR 0039 section 10 declined to add
	// a capacity class for the same reason, and ADR 0040 section 17 declines the
	// matching finding.
	CodeSessionEstablishmentFailed domain.FindingCode = "POSTGRES_SESSION_ESTABLISHMENT_FAILED"
)

const (
	summaryDatabaseNotFound = "PostgreSQL reported that the requested database is not available"
	detailDatabaseNotFound  = "This endpoint accepted the connection's authentication and then " +
		"refused it with the code whose own meaning is an absent database.\n" +
		"Several distinct conditions produce that code — no catalog entry, an entry that " +
		"disappeared during the lookup, and an entry whose files are missing — so svcdoctor " +
		"reports the absence and not its cause."
	// Deliberately short of "create the database": the corruption variant makes
	// creating it the wrong action, and svcdoctor cannot tell the cases apart.
	// "Verify it exists and is available" is true advice under all three.
	recommendDatabaseNotFound = "Verify that the database name this run requested exists and is " +
		"available at this endpoint"

	summaryDatabaseConnectDenied = "The PostgreSQL endpoint denied this session CONNECT access " +
		"to the requested database"
	detailDatabaseConnectDenied = "This endpoint accepted the connection's authentication and " +
		"then denied it access to the requested database.\n" +
		"It says nothing about any other privilege: svcdoctor issues no statement, so no other " +
		"privilege check can have run."
	// Names what to review and emits no SQL. svcdoctor suggests where to look
	// and never what to run.
	recommendDatabaseConnectDenied = "Review the CONNECT privilege on the requested database for " +
		"the role this run used"

	// Fixed by ADR 0040 section 18, word for word.
	summarySessionEstablishmentFailed = "The PostgreSQL session did not reach ReadyForQuery " +
		"after authentication completed"
	detailSessionEstablishmentFailed = "This endpoint accepted the connection's authentication " +
		"and then ended the session before it was usable."
	recommendSessionEstablishmentFailed = "Review this endpoint's log for the session it " +
		"accepted and then closed"
)

// authMethodNone is the normalized name for an endpoint stating it wants no
// authentication. On such a path no authentication node exists.
const authMethodNone = "ok"

// Session reports what happened between authentication and ReadyForQuery.
//
// It is a diagnosis.Rule. Two escalations and one floor, disjoint on the failure
// class, and all three gated on the same precondition.
//
// # Every claim here begins "this endpoint completed authentication"
//
// So every finding must cite what establishes that, rather than assert it. The
// parent test is that citation: the session node's parent must be a passing
// authentication node, or a passing startup node that recorded the endpoint
// demanding no authentication at all.
//
// Both halves are required. Demanding an authentication parent alone would
// silently stop firing on every `trust` deployment, where the adapter records no
// authentication node **because svcdoctor presented nothing** and claiming a
// passing authentication would be an overclaim (ADR 0038 section 12).
//
// # A malformed graph withholds rather than guesses
//
// A session node whose parent satisfies neither half produces **no finding**.
// That is a shape no producer emits, and a rule that guessed at one would be
// inventing the very half of its claim it cannot cite — which is
// internal/diagnosis/kafka's treatment of a malformed anchor, applied unchanged.
func Session(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, node := range g.Nodes() {
		if node.Step() != servicepostgres.StepSession {
			continue
		}
		finding, ok := evaluateSession(g, node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateSession applies ADR 0040 sections 16 and 17 to one session node.
func evaluateSession(g domain.Graph, node domain.Evidence) (domain.Finding, bool) {
	// A passing session is not a finding. Specifically it is not a claim that a
	// backend is healthy, reachable, writable, primary or replica: a pooler
	// served a complete passing session with its backend stopped, measured.
	if node.State() != domain.StateFail {
		return domain.Finding{}, false
	}

	proof, ok := authenticationProof(g, node)
	if !ok {
		return domain.Finding{}, false
	}

	refs := []domain.EvidenceID{node.ID(), proof.ID()}
	// The startup node carries the requested database as an identity attribute,
	// which is what "the requested database" in the prose refers to. When the
	// proof *is* the startup node the reference is the same identifier, and
	// NewFinding deduplicates.
	if startup, found := startupOf(g, proof); found {
		refs = append(refs, startup.ID())
	}

	switch node.FailureClass() {
	case domain.FailureResourceNotFound:
		return build(domain.FindingInput{
			Code:       CodeDatabaseNotFound,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryDatabaseNotFound,
			Detail:     detailDatabaseNotFound,
			// A catalog lookup does not vary by the source of the connection.
			VantageDependent: false,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendDatabaseNotFound),
		})

	case domain.FailureAuthzDenied:
		return build(domain.FindingInput{
			Code:       CodeDatabaseConnectDenied,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryDatabaseConnectDenied,
			Detail:     detailDatabaseConnectDenied,
			// CONNECT is held per role per database, not per source address.
			VantageDependent: false,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendDatabaseConnectDenied),
		})

	default:
		return build(domain.FindingInput{
			Code:       CodeSessionEstablishmentFailed,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summarySessionEstablishmentFailed,
			Detail:     floorDetail(detailSessionEstablishmentFailed, node),
			// A floor attributes no cause and therefore cannot exclude a
			// source-keyed one.
			VantageDependent: true,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendSessionEstablishmentFailed),
		})
	}
}

// authenticationProof returns the parent that establishes that authentication
// completed, when exactly one does.
//
// Exactly one, for the reason parentWithStep requires it: a finding that cites
// "the" proof has no defensible answer when a graph offers two.
func authenticationProof(g domain.Graph, session domain.Evidence) (domain.Evidence, bool) {
	var found domain.Evidence
	count := 0

	for _, id := range g.Parents(session.ID()) {
		parent, ok := g.Node(id)
		if !ok || parent.State() != domain.StatePass {
			continue
		}

		switch parent.Step() {
		case servicepostgres.StepAuthentication:
			// A passing authentication node means the signature verified and
			// the endpoint said Ok. Both halves, which is what the producer's
			// PASS commits to.
		case servicepostgres.StepStartup:
			// The trust path. The startup node must actually record that the
			// endpoint demanded nothing; a passing startup that demanded SASL
			// and then has a session node beneath it without an authentication
			// node is a shape no producer emits, and is not accepted here.
			method, hasMethod := stringAttr(parent, servicepostgres.AttrAuthMethod)
			if !hasMethod || method != authMethodNone {
				continue
			}
		default:
			continue
		}

		found = parent
		count++
	}

	return found, count == 1
}

// startupOf returns the startup node a proof node names, which is the proof
// itself on the trust path and its parent otherwise.
func startupOf(g domain.Graph, proof domain.Evidence) (domain.Evidence, bool) {
	if proof.Step() == servicepostgres.StepStartup {
		return proof, true
	}
	return parentWithStep(g, proof, servicepostgres.StepStartup)
}
