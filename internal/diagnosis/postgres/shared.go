package postgres

import (
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// CodeConnectionNotPermitted reports an endpoint refusing a connection on the
// basis of who is connecting and from where, before any credential is evaluated.
//
// It is the only code in this package produced by two rules, because the
// evidence it reads can land at two steps: a host-based access decision arrives
// at `postgres.startup` when it precedes the authentication request, and at
// `postgres.authentication` when it does not. Both steps' classifiers reached
// `AUTHZ_NOT_PERMITTED` independently and for the same documented reason, so the
// rules read the class rather than a SQLSTATE — which is what keeps this from
// being the shared SQLSTATE table ADR 0039 section 7.1 forbids.
//
// The constant lives here rather than beside one of the two rules precisely
// because neither owns it.
const CodeConnectionNotPermitted domain.FindingCode = "POSTGRES_CONNECTION_NOT_PERMITTED"

// The prose for CodeConnectionNotPermitted, shared by both producing rules so
// that the same claim cannot drift into two wordings.
//
// "this connection" and "before evaluating any credential" are both
// load-bearing and neither may be generalized: the refusal arrived before any
// authentication material was presented, so it says nothing about the credential
// and nothing about the role in general.
const (
	summaryNotPermitted = "The PostgreSQL endpoint refused this connection before evaluating any credential"

	detailNotPermitted = "The refusal arrived before any credential was presented, so it is a " +
		"decision about the connecting role and the address it connected from rather than " +
		"about the credential itself.\n" +
		"It is relative to this vantage point: host-based access rules match on the source " +
		"address, so the same role may be permitted from elsewhere."

	recommendNotPermitted = "Review this endpoint's host-based access rules for the role this " +
		"run used and for the address this run connected from"
)

// notPermitted builds the finding both rules produce.
//
// The layer is passed rather than derived, because the claim's layer is the
// anchor's own and the two anchors sit at different ones: L4 at startup, L5 at
// authentication. Deriving it from the node would work today and would silently
// follow a producer that changed its mind, which is not the same thing.
func notPermitted(anchor domain.Evidence, layer domain.Layer, refs []domain.EvidenceID) (domain.Finding, bool) {
	return build(domain.FindingInput{
		Code:     CodeConnectionNotPermitted,
		Kind:     domain.FindingKindConfirmed,
		Severity: domain.SeverityError,
		// Direct evidence: the peer asserted the refusal with a code whose own
		// meaning is that it evaluated no credential.
		Confidence: domain.ConfidenceHigh,
		Layer:      layer,
		Subject:    anchor.Subject(),
		Summary:    summaryNotPermitted,
		Detail:     detailNotPermitted,
		// The mechanism by which the answer varies with position is known and
		// documented — host-based rules match the source address — which makes
		// this the one finding in the set whose vantage dependence is directly
		// proved rather than merely not excludable (ADR 0040 section 6.1).
		VantageDependent: true,
		EvidenceRefs:     refs,
		Recommendations:  recommend(recommendNotPermitted),
	})
}

// build assembles a finding, folding the constructor's error.
//
// Every caller supplies a constant code, a validated domain value taken from a
// node the graph already accepted, and prose built from constants plus values
// that cannot carry a control character. The error is therefore unreachable, and
// TestEveryAuthorizedShapeBuildsAValidFinding drives the whole matrix so the
// omission is proven rather than assumed.
//
// A rule must not respond to a rejected finding by quietly returning fewer:
// silently omitting a conclusion is the failure mode the project's claim
// discipline exists to prevent. That is why this returns a bool the callers
// propagate and the test asserts is never false.
func build(in domain.FindingInput) (domain.Finding, bool) {
	finding, err := domain.NewFinding(in)
	if err != nil {
		return domain.Finding{}, false
	}
	return finding, true
}

// recommend wraps one action, dropping it only if the constant were malformed.
//
// TestEveryRecommendationTextIsValid pins that none is.
func recommend(action string) []domain.Recommendation {
	recommendation, err := domain.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []domain.Recommendation{recommendation}
}

// parentWithStep returns the single parent of node at the given step, when
// exactly one exists.
//
// Exactly one is required rather than the first found. A finding that references
// "the" startup node has no defensible answer to which one to cite when a graph
// offers two, and picking one by traversal order would make the output depend on
// how the graph was assembled. Kafka's metadataExchange requires the same thing
// for the same reason.
func parentWithStep(g domain.Graph, node domain.Evidence, step domain.Step) (domain.Evidence, bool) {
	var found domain.Evidence
	count := 0
	for _, id := range g.Parents(node.ID()) {
		parent, ok := g.Node(id)
		if !ok || parent.Step() != step {
			continue
		}
		found = parent
		count++
	}
	return found, count == 1
}

// stringAttr reads a string-valued attribute.
func stringAttr(node domain.Evidence, key domain.AttributeKey) (string, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return "", false
	}
	return value.Str()
}

// boolAttr reads a bool-valued attribute.
func boolAttr(node domain.Evidence, key domain.AttributeKey) (bool, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return false, false
	}
	return value.Bool()
}

// The sentences a floor finding's detail may add, and the conditions under which
// each is true.
//
// The attribution sentence is **not unconditional**, and that is the correction
// ADR 0040 section 8.1 makes normative. A class that already names a stronger
// fact — an unsupported protocol version, a malformed frame, a peer that closed
// — makes "svcdoctor could not attribute this" false. Understating the evidence
// is a different error from overstating it and is still an error.
const (
	sentenceUnattributable = "svcdoctor could not attribute this outcome to a specific cause."

	// Stated as the observation it is. It may not become "a pooler answered":
	// the field's absence is equally consistent with a connection pooler, a
	// proxy and a pre-9.6 server, so concluding a peer implementation from it
	// would be inventing an identity (ADR 0040 section 18.1).
	sentenceNotNative = "The response did not carry the non-localized severity field that a " +
		"PostgreSQL backend has sent since 9.6."

	// sentenceConnectionLimitReached restates the endpoint's own condition and
	// stops there.
	//
	// 53300 is PostgreSQL's too_many_connections. The peer named it; svcdoctor
	// is not inferring it from position, from timing or from a message, exactly
	// as 3D000 and 42501 are handled a step away.
	//
	// **It is scoped to the attempt, not to the endpoint.** PostgreSQL raises
	// 53300 whenever a connection limit applicable to the session being admitted
	// has been reached, and it has several — max_connections, the reserved-slot
	// margins, a database's CONNECTION LIMIT and a role's — and the ErrorResponse
	// names none of them. A role created with CONNECTION LIMIT 0 produces this
	// code on a server with connections to spare, which is what the integration
	// fixture does, so "no connection slot was available" was a stronger sentence
	// than the code carries. It was corrected rather than kept, here as well as in
	// the claim, so the two windows say the same thing about the same five
	// characters.
	//
	// What it deliberately does **not** say, because none of it follows from the
	// code: which limit was reached, that max_connections is configured too low,
	// that a client is leaking connections, that a pool is misconfigured, that
	// load spiked, or that the condition is persistent rather than the instant
	// this run measured. A second run a moment later may connect. The remedy
	// differs for every one of those causes, and the evidence separates none of
	// them.
	sentenceConnectionLimitReached = "That is the endpoint's own too_many_connections " +
		"condition: a connection limit that applied to the attempted session had been " +
		"reached. The response does not say which limit."
)

// namedConditions are the SQLSTATEs whose condition svcdoctor may restate.
//
// Membership requires two things, and both were missing until Phase 7.3A. The
// code has to name a condition specifically enough that restating it adds
// information beyond the five characters already printed — 08P01 fails this,
// because pgBouncer returns it for everything. And svcdoctor has to have watched
// a real endpoint produce it, so the entry records a measurement rather than a
// reading of the PostgreSQL source.
//
// It is deliberately not a SQLSTATE dictionary. ADR 0039 section 7.1 refuses one
// because the answerable question is *what does this code prove here*, not *what
// does this code mean*; every entry below has to be true in any window a floor
// finding can be raised from, since floorDetail serves all three. A code whose
// meaning depends on the window belongs in that window's classifier, where 3D000
// and 42501 already are.
var namedConditions = map[string]string{
	// Measured in Phase 7.3A against PostgreSQL 18.6: max_connections reached,
	// authentication completed, session refused before ReadyForQuery.
	"53300": sentenceConnectionLimitReached,
}

// observedDetail appends a node's own recorded observations to a base sentence.
//
// It is the half of floorDetail that states what was seen rather than what could
// not be attributed: the SQLSTATE verbatim, and the absence of the non-localized
// severity field when that is what happened. A finding that already names the
// endpoint's condition needs exactly those two and neither of floorDetail's
// closing sentences — the attribution sentence would be false, and the named
// condition would repeat the base.
//
// The SQLSTATE is rendered **verbatim and never translated**, for the reason
// floorDetail gives. Deterministic by construction: the parts are appended in a
// fixed order and nothing is collected from a map.
func observedDetail(base string, node domain.Evidence) string {
	parts := []string{base}
	if code, ok := stringAttr(node, servicepostgres.AttrSQLState); ok && code != "" {
		parts = append(parts, "The endpoint reported SQLSTATE "+code+".")
	}
	if native, ok := boolAttr(node, servicepostgres.AttrErrorIsNative); ok && !native {
		parts = append(parts, sentenceNotNative)
	}
	return strings.Join(parts, "\n")
}

// floorDetail assembles a floor finding's detail from the node's own record.
//
// Deterministic by construction: the parts are appended in a fixed order and
// nothing is collected from a map, so the same node yields the same bytes.
//
// The SQLSTATE is rendered **verbatim and never translated**. Five characters
// carry no identity, they are already a structured attribute a consumer should
// read instead, and repeating them helps a human without inventing a meaning.
// Turning one into English is the shared dictionary ADR 0039 section 7.1 exists
// to prevent.
func floorDetail(base string, node domain.Evidence) string {
	parts := []string{base}

	named := ""
	if code, ok := stringAttr(node, servicepostgres.AttrSQLState); ok && code != "" {
		parts = append(parts, "The endpoint reported SQLSTATE "+code+".")
		named = namedConditions[code]
	}
	if native, ok := boolAttr(node, servicepostgres.AttrErrorIsNative); ok && !native {
		parts = append(parts, sentenceNotNative)
	}
	switch {
	case named != "":
		// The peer named the condition, so the attribution sentence would be
		// false. ADR 0040 section 8.1 already made that sentence conditional for
		// exactly this reason: understating the evidence is a different error
		// from overstating it and is still an error. Phase 7.3A measured the
		// understatement — an endpoint reported 53300 and svcdoctor printed the
		// code and "could not attribute this outcome to a specific cause" in the
		// same finding, which is a contradiction a reader has to resolve.
		parts = append(parts, named)
	case node.FailureClass() == domain.FailureProtocolUnexpectedResponse:
		parts = append(parts, sentenceUnattributable)
	}

	return strings.Join(parts, "\n")
}

// projectAdvice runs one suggestion through the Phase 10.1a guardrails and
// returns what a report can carry today.
//
// It is the same helper internal/diagnosis/kafka holds, deliberately copied
// rather than shared. The two are four lines of composition over exported
// generic functions, and the alternative — an exported helper on
// internal/diagnosis — would put a *findings* constructor in the package whose
// whole contract is that it knows no service's claims. ADR 0084 section 9 made
// the same call for Kafka; nothing has changed to make one shared copy the
// smaller thing.
//
// # Why the classification does not reach the report
//
// ADR 0082 section 2.1 puts kind, safety, rationale and self-collectability on
// domain.Recommendation, additively, and Phase 10.3 does not move them: that is
// a generic change touching every service's renderer and every golden report.
// What it does do is refuse to write advice the classification would have
// rejected — the producible-class check, the read-only requirement on next
// evidence, the confidence gate and the no-executable-command validator all run
// here, at construction.
//
// A rejected suggestion yields no recommendation at all. Emitting an
// unclassified string because the classified one was refused would be the
// guardrail deleting itself.
func projectAdvice(
	in diagnosis.AdviceInput, kind domain.FindingKind, confidence domain.Confidence,
) []domain.Recommendation {
	advice, err := diagnosis.NewAdvice(in)
	if err != nil {
		return nil
	}
	if err := diagnosis.AdmitAdvice(kind, confidence, advice); err != nil {
		return nil
	}
	recommendation, err := domain.NewRecommendation(advice.Action())
	if err != nil {
		return nil
	}
	return []domain.Recommendation{recommendation}
}
