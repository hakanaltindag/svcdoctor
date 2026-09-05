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

	// CodeConnectionLimitReached is the endpoint's own too_many_connections
	// condition, restated as a claim rather than as a sentence inside a floor.
	//
	// # Why this exists now, when ADR 0040 section 17 declined it
	//
	// That section declined it in one sentence with a stated dependency: ADR 0039
	// section 10 "declined to add a capacity class for it — one producer and no
	// authorizing record is not enough to grow a service-neutral vocabulary — and
	// this record declines the matching finding **for the same reason**". Phase
	// 8.1 satisfied both halves of that condition and added
	// `RESOURCE_LIMIT_REACHED`, with RabbitMQ's three ceilings as the additional
	// producers and ADR 0069 as the record. The reason was gone; the refusal was
	// not. ADR 0085 section 3 closes it.
	//
	// The other half of section 17's argument stands and shapes the wording: a
	// pooler reports its own client limit as `08P01`, so svcdoctor cannot tell
	// where the limit that was reached is enforced. That is why the claim is about
	// **this endpoint's** refusal of **this session** and never about
	// "PostgreSQL", a backend, or where the limit lives.
	//
	// # What it proves, and the much longer list of what it does not
	//
	// It proves that **this endpoint authoritatively rejected this attempted
	// session** with PostgreSQL's `too_many_connections` condition, named by the
	// peer itself in a field its own protocol defines. `AuthorityDirect`, so
	// `HIGH` — the peer said so and svcdoctor is repeating it.
	//
	// **It is a statement about one attempted session and not about the endpoint's
	// capacity.** `53300` is raised whenever *some* connection limit applicable to
	// the session being admitted has been reached, and PostgreSQL has more than
	// one: `max_connections`, the reserved-slot margins, a database's
	// `CONNECTION LIMIT` and a role's. The ErrorResponse names none of them. This
	// repository's own integration fixture is the proof — a role created with
	// `CONNECTION LIMIT 0` yields `53300` on every login while the server has
	// connections to spare — so "the endpoint has no connection left" is a
	// **stronger claim than the evidence carries** and the prose below never makes
	// it. Which limit applied can depend on the session's own context, the role
	// most obviously, so a different role at the same instant may be admitted.
	//
	// It does **not** prove a connection leak, a pool sized wrongly, a setting
	// configured too low, a traffic spike, memory pressure, or that the condition
	// outlasted the instant it was observed. A second run a moment later may
	// connect. Every one of those is a *cause*, 53300 separates none of them, and
	// the remedy differs for each — which is exactly why the finding carries a
	// next-evidence recommendation instead of a remediation.
	CodeConnectionLimitReached domain.FindingCode = "POSTGRES_CONNECTION_LIMIT_REACHED"

	// CodeSessionEstablishmentFailed is the L5 session floor.
	//
	// It no longer carries the connection-limit refusal — CodeConnectionLimitReached
	// does, above — and it still does **not** become "the endpoint is out of
	// connections" for anything else: a code svcdoctor could not normalize proves
	// no condition, and a pooler reports its own client limit as `08P01`.
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

	// The connection-limit claim, fixed by ADR 0085 section 3.
	//
	// **"this session" and "this endpoint" are both load-bearing** and neither may
	// be generalized. The first is the whole epistemic content of the finding:
	// `53300` is the endpoint rejecting *the session being admitted*, at one
	// instant, against whichever applicable limit was reached — and it is not a
	// statement that the endpoint had no connection left to give. The second is
	// ADR 0040 section 18: svcdoctor does not know whether a backend, a pooler or
	// a proxy answered, so it reports the refusal at the endpoint it spoke to.
	summaryConnectionLimitReached = "The PostgreSQL endpoint refused this session with its " +
		"too_many_connections condition"

	// The detail states the basis, then states the boundary of the claim.
	//
	// The boundary has two halves and the first is the one Phase 10.3 got wrong.
	// **Scope**: `53300` says a connection limit applicable to the session being
	// admitted was reached, and PostgreSQL has several — so the detail says
	// "a connection limit that applied to this attempted session" and never "no
	// slot was available", which would assert an endpoint-wide property the
	// response does not carry. This repository's own fixture creates the
	// counterexample with `CONNECTION LIMIT 0` on a role. **Cause**: the set of
	// things 53300 does not separate — a leak, a limit set too low, a pool sized
	// wrongly, a burst of traffic, and a condition that has already passed. None
	// is named here, because naming one to deny it puts the word in the report,
	// and the scope sentences are written positively for the same reason.
	detailConnectionLimitReached = "This endpoint accepted the connection's authentication " +
		"and then refused the session, reporting its own too_many_connections condition: " +
		"a connection limit that applied to this attempted session had been reached.\n" +
		"The endpoint named that condition itself, in a field its protocol defines, so the " +
		"refusal is what was observed rather than what svcdoctor inferred. It is a " +
		"statement about this one attempt, at the moment it was made.\n" +
		"Which limit was reached is not in the response. More than one connection limit can " +
		"govern a single PostgreSQL session, and which one governs depends on the session's " +
		"own context — the role this run authenticated as, among others.\n" +
		"The response also carries nothing about why that limit was reached, how long it had " +
		"been reached, or where it is enforced: an element in the path may impose a ceiling " +
		"of its own and report it under a different code entirely. A later attempt may " +
		"succeed."

	// The next observation, and deliberately not an action.
	//
	// **The identification step comes first, and it is not svcdoctor's to skip.**
	// The response names no limit, PostgreSQL applies more than one to a single
	// admission, and an operator sent straight to a comparison has been told
	// implicitly which setting to look at. So the advice asks for the applicable
	// set to be established and only then compared — and it names no member of
	// that set, not `max_connections`, not a database or role `CONNECTION LIMIT`,
	// and not a reserved margin.
	//
	// "increase the connection limit" is refused permanently: it can worsen
	// memory pressure and it hides an application that is holding connections it
	// does not need. svcdoctor does not know which of those is happening, and the
	// observation that would tell an operator is a comparison it cannot make
	// itself (ADR 0082 section 2.4).
	recommendConnectionLimitReached = "Identify the connection limits applicable to this " +
		"attempted session and compare their current usage with their configured limits"

	rationaleConnectionLimitReached = "The endpoint stated that a connection limit applying " +
		"to this attempted session had been reached, and named neither the limit nor how " +
		"much of it was in use; establishing which limits applied and comparing each one's " +
		"usage with its configured value is what identifies the limit that was reached and " +
		"whether it still is."

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

	case domain.FailureResourceLimitReached:
		return build(domain.FindingInput{
			Code: CodeConnectionLimitReached,
			Kind: domain.FindingKindConfirmed,
			// A session was refused, which prevents correct use. The severity is
			// the impact of this refusal and is not a judgement about how the
			// endpoint is configured.
			Severity: domain.SeverityError,
			// AuthorityDirect: the peer named the condition in its own protocol,
			// in a field that protocol defines. It is the ladder's first
			// admission test and the only one that admits HIGH here
			// (ADR 0081 section 2.3).
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryConnectionLimitReached,
			Detail:     observedDetail(detailConnectionLimitReached, node),
			// `false` means exactly one thing: **this claim is not inferred
			// from a source-address-dependent observation.** The endpoint
			// stated the condition itself, in its own protocol, and it would
			// have stated it to any client whose session met the same limit;
			// nothing here is read off where svcdoctor happened to dial from,
			// which is the one thing vantage dependence is about (ADR 0012).
			//
			// It does **not** mean the condition is an endpoint-wide invariant.
			// The limit that applied may depend on the session's own context —
			// the role most obviously — so another session at the same instant
			// may be admitted, and this flag makes no claim either way. Vantage
			// dependence is a property of how a claim was *derived*, not of how
			// widely what it asserts holds. The two sibling escalations are
			// `false` on the same ground (ADR 0040 section 6.1).
			VantageDependent: false,
			EvidenceRefs:     refs,
			Recommendations: diagnosis.Recommend(diagnosis.AdviceInput{
				Kind:      diagnosis.AdviceKindNextEvidence,
				Safety:    diagnosis.SafetyCompare,
				Action:    recommendConnectionLimitReached,
				Rationale: rationaleConnectionLimitReached,
				// svcdoctor cannot take it in any run: PostgreSQL BASIC executes
				// no SQL, and the credential may not hold the privilege even if
				// it did. Saying so is more useful than implying it looked
				// (ADR 0082 section 2.4).
				SelfCollectable: false,
			}, domain.FindingKindConfirmed, domain.ConfidenceHigh),
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
