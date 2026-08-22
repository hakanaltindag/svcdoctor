package postgres

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The codes the authentication step can produce.
//
// Six, plus CodeConnectionNotPermitted which it shares with the startup rule.
// They are disjoint on (state, failure class), so one node yields exactly one.
const (
	// CodeCredentialsRejected: the endpoint refused what svcdoctor presented.
	//
	// **The class alone is the predicate**, with no SQLSTATE clause. That is
	// sound only because Phase 4.6a.5 corrected the producer: until then
	// `AUTH_CREDENTIALS_REJECTED` also carried a server-signature mismatch,
	// which is the opposite direction, and the clause was a workaround for a
	// class that was lying. Every remaining producer — PostgreSQL's `28P01` and
	// its two SCRAM refusal tokens, and Kafka's `SASL_AUTHENTICATION_FAILED` —
	// is the peer refusing what it was presented.
	//nolint:gosec // G101: this is a public finding code, not a credential. The
	// rule fires on the identifier containing "Credentials"; nothing here holds
	// or derives a secret, and depguard denies this package internal/security
	// outright.
	CodeCredentialsRejected domain.FindingCode = "POSTGRES_CREDENTIALS_REJECTED"

	// CodePeerVerificationFailed: the endpoint could not prove it knows the
	// credential.
	//
	// The other direction, and reachable only after the endpoint has *accepted*
	// svcdoctor's material — a peer that rejects the proof never sends a
	// signature at all. Reporting it as a rejected credential would state the
	// opposite of what happened, which is what ADR 0040 section 5.1 fixed.
	CodePeerVerificationFailed domain.FindingCode = "POSTGRES_PEER_VERIFICATION_FAILED"

	// CodeMechanismUnavailable: no authentication mechanism in common.
	//
	// One code for both directions of the gap, deliberately. Whose gap it is
	// moves with svcdoctor's own capability — a `-PLUS`-only endpoint stops
	// being svcdoctor's gap the day channel binding is implemented — and a
	// public code whose boundary shifts on a svcdoctor release is a code
	// consumers cannot branch on. The distinction survives losslessly on the
	// node's State and FailureClass, and in this finding's severity.
	CodeMechanismUnavailable domain.FindingCode = "POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE"

	// CodeUnsupportedBySvcdoctor: the mechanism was available and performed, and
	// svcdoctor declined to complete it for a limitation of its own.
	//
	// Not merged with CodeMechanismUnavailable: there, no mechanism was in
	// common; here one was, and svcdoctor stopped. Different claims.
	CodeUnsupportedBySvcdoctor domain.FindingCode = "POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR"

	// CodeCredentialWithheld: svcdoctor sent no credential, by policy.
	//nolint:gosec // G101: a public finding code, not a credential. See
	// CodeCredentialsRejected.
	CodeCredentialWithheld domain.FindingCode = "POSTGRES_CREDENTIAL_WITHHELD"

	// CodeCredentialNotConfigured: the endpoint demanded authentication and the
	// run held nothing to present.
	//
	// # Why "not configured" and not "missing" or "required"
	//
	// `REQUIRED` would name the endpoint's demand, which the startup node already
	// records as postgres.auth_method and which is not the news. `MISSING`
	// suggests something was lost. The condition is that this run was not given a
	// credential for this endpoint — a statement about the run's configuration,
	// which is the thing an operator changes.
	//
	// It is the sibling of CodeCredentialWithheld and never its synonym.
	// Withheld means a credential exists and svcdoctor refused to send it over
	// this channel; this means there was none to send. Same step, same state,
	// different classes, and different next actions: one sends a reader to the
	// channel, the other to the run's configuration.
	//nolint:gosec // G101: a public finding code, not a credential. The rule
	// fires on the identifier containing "Credential"; this constant is the
	// reverse of a secret — it names the absence of one.
	CodeCredentialNotConfigured domain.FindingCode = "POSTGRES_CREDENTIAL_NOT_CONFIGURED"

	// CodeAuthenticationFailed is the L5 floor.
	CodeAuthenticationFailed domain.FindingCode = "POSTGRES_AUTHENTICATION_FAILED"
)

const (
	summaryCredentialsRejected = "The PostgreSQL endpoint rejected the authentication material " +
		"svcdoctor presented"
	detailCredentialsRejected = "The endpoint answered svcdoctor's proof with its own refusal.\n" +
		"That response is issued identically for a wrong secret, an unknown role, a corrupted " +
		"proof and a correct secret that needed Unicode preparation — deliberately, so that a " +
		"client cannot determine which. svcdoctor reports the refusal and not a cause."
	recommendCredentialsRejected = "Verify the credential configured for this endpoint and the " +
		"role it is meant to authenticate as; the endpoint's own log is the only place a wrong " +
		"secret and an unknown role are distinguished"

	summaryPeerVerificationFailed = "The PostgreSQL endpoint failed authentication proof verification"
	detailPeerVerificationFailed  = "This authentication mechanism authenticates both parties. " +
		"The endpoint accepted the material svcdoctor presented, and then presented a value of " +
		"its own that did not verify against the configured credential.\n" +
		"The observation does not say why: an endpoint that does not hold this credential, " +
		"something answering in its place, and a defective implementation are indistinguishable " +
		"from what was exchanged."
	recommendPeerVerificationFailed = "Verify the credential configured for this endpoint, and " +
		"establish what this endpoint is before presenting the credential again"

	summaryMechanismUnavailable = "The PostgreSQL endpoint and svcdoctor have no authentication " +
		"mechanism in common for this connection"
	detailMechanismUnavailable = "No credential was presented, so nothing is known about it.\n" +
		"What the endpoint demanded or advertised is recorded on the referenced startup node."
	recommendMechanismNotOffered = "Check which authentication mechanisms this endpoint offers " +
		"for the role this run used and from the address this run connected from"
	recommendMechanismUnsupported = "Diagnose this endpoint with a client that performs the " +
		"authentication method it demands, or configure a mechanism svcdoctor performs for the " +
		"role this run used"

	summaryUnsupportedBySvcdoctor = "svcdoctor could not complete the authentication this " +
		"PostgreSQL endpoint required"
	// "neither accepted nor rejected" is the sentence that earns this finding
	// its place: an UNKNOWN node must not read as a refusal.
	detailUnsupportedBySvcdoctor = "svcdoctor performs SCRAM-SHA-256 over printable-ASCII " +
		"passwords and a bounded iteration count, and declines the rest. The limitation is " +
		"svcdoctor's own.\n" +
		"The credential was neither accepted nor rejected."
	recommendUnsupportedBySvcdoctor = "Re-run against a role whose password is printable ASCII, " +
		"or diagnose this endpoint with a client that implements the full mechanism"

	summaryCredentialWithheld = "svcdoctor withheld the credential because this connection did " +
		"not meet the credential-transport policy"
	detailCredentialWithheld = "svcdoctor deliberately sent no credential material: the " +
		"referenced blocking node records what this connection proved, and this run's policy " +
		"requires a verified TLS channel before a password crosses it.\n" +
		"Nothing was presented, so no refusal took place and nothing is known about the " +
		"credential."
	recommendCredentialWithheld = "Establish a verified TLS channel to this endpoint before " +
		"presenting a credential, or re-run with the transport policy this run is meant to use"

	// Fixed by ADR 0040 section 14, word for word.
	summaryAuthenticationFailed = "The PostgreSQL authentication exchange did not complete successfully"
	detailAuthenticationFailed  = "The exchange reached this endpoint and ended without a " +
		"completed authentication."
	recommendAuthenticationFailed = "Review this endpoint's authentication log for the role this " +
		"run used"
)

// Authentication reports what happened at the authentication step.
//
// It is a diagnosis.Rule. Six escalations and one floor, disjoint on
// (state, failure class): a node matches at most one, which a test asserts
// rather than a precedence list implying.
//
// # Escalations are checked against the class, never against a SQLSTATE
//
// The adapter classified per step, because the only answerable question is what
// a code proves *there* (ADR 0039 section 7.1). A rule that re-read the SQLSTATE
// would be rebuilding the shared dictionary that decision forbids, and would
// also be wrong: `08P01` is a pooler's substitute for having no code at all.
//
// # UNKNOWN and SKIPPED do not fall through to the floor
//
// The floor requires FAIL. An UNKNOWN node is either a svcdoctor gap — which has
// its own two codes — or svcdoctor's own budget expiring, which produces
// nothing. A SKIPPED node is the policy refusal, which has its own code. Nothing
// else reaches the floor, which is why the floor's claim can be as flat as it is.
func Authentication(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	for _, node := range g.Nodes() {
		if node.Step() != servicepostgres.StepAuthentication {
			continue
		}
		finding, ok := evaluateAuthentication(g, node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateAuthentication applies ADR 0040 sections 9 through 15 to one node.
func evaluateAuthentication(g domain.Graph, node domain.Evidence) (domain.Finding, bool) {
	// The startup node carries the role and database as identity attributes and
	// the advertised mechanism list, so it is the half a reader needs to check
	// what the claim is about. It is cited when it exists; a node without one is
	// a graph shape no producer emits, and the finding stays truthful without it
	// rather than being withheld over a decoration.
	refs := []domain.EvidenceID{node.ID()}
	startup, hasStartup := parentWithStep(g, node, servicepostgres.StepStartup)
	if hasStartup {
		refs = append(refs, startup.ID())
	}

	switch node.State() {
	case domain.StateFail:
		return failedAuthentication(node, refs)
	case domain.StateUnknown:
		return unknownAuthentication(node, refs)
	case domain.StateSkipped:
		return skippedAuthentication(g, node, refs)
	case domain.StatePass, domain.StateDegraded:
		// A passing authentication is not a finding: this package produces no
		// success finding at all. DEGRADED is a shape no producer here emits.
		return domain.Finding{}, false
	}
	return domain.Finding{}, false
}

// failedAuthentication handles the four FAIL outcomes and the floor.
func failedAuthentication(node domain.Evidence, refs []domain.EvidenceID) (domain.Finding, bool) {
	switch node.FailureClass() {
	case domain.FailureAuthCredentialsRejected:
		return build(domain.FindingInput{
			Code:       CodeCredentialsRejected,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryCredentialsRejected,
			Detail:     detailCredentialsRejected,
			// A completed evaluation: the endpoint was shown material and
			// refused it. That record does not become false when a different
			// observer is treated differently.
			VantageDependent: false,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendCredentialsRejected),
		})

	case domain.FailureAuthPeerVerificationFailed:
		return build(domain.FindingInput{
			Code:       CodePeerVerificationFailed,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryPeerVerificationFailed,
			Detail:     detailPeerVerificationFailed,
			// Something present on one path and absent from another can answer
			// in the endpoint's place, so the answer can differ between two
			// positions reaching the same peer. The flag says the observation
			// was made from here and leaves the cause open — which is also the
			// useful thing to say, because re-observing from elsewhere is the
			// measurement that would narrow it.
			VantageDependent: true,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendPeerVerificationFailed),
		})

	case domain.FailureAuthzNotPermitted:
		return notPermitted(node, domain.LayerAuth, refs)

	case domain.FailureAuthMechanismNotOffered:
		// The endpoint positively evidenced that it offers nothing svcdoctor
		// performs. WARN and not ERROR: that is a real problem for this
		// diagnosis, and nothing here proves the operator's own client cannot
		// authenticate.
		return mechanismUnavailable(node, domain.SeverityWarn, recommendMechanismNotOffered, refs)

	default:
		return build(domain.FindingInput{
			Code:       CodeAuthenticationFailed,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryAuthenticationFailed,
			Detail:     floorDetail(detailAuthenticationFailed, node),
			// A floor attributes no cause and therefore cannot exclude a
			// source-keyed one.
			VantageDependent: true,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendAuthenticationFailed),
		})
	}
}

// unknownAuthentication handles the two svcdoctor gaps.
//
// Neither is a defect in the endpoint, and neither may be reported as one:
// docs/ARCHITECTURE.md and domain/state.go both require that an unsupported
// capability is not a failure of the thing being inspected. Anything else
// UNKNOWN — a local timeout, a cancelled run — produces nothing, because nothing
// was learned about the endpoint.
func unknownAuthentication(node domain.Evidence, refs []domain.EvidenceID) (domain.Finding, bool) {
	switch node.FailureClass() {
	case domain.FailureAuthMechanismUnsupported:
		// INFO: a gap in svcdoctor. Grading a tool gap higher would spend the
		// endpoint's severity budget on svcdoctor's own coverage.
		return mechanismUnavailable(node, domain.SeverityInfo, recommendMechanismUnsupported, refs)

	case domain.FailureExecUnsupportedBySvcdoctor:
		return build(domain.FindingInput{
			Code:       CodeUnsupportedBySvcdoctor,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityInfo,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Subject:    node.Subject(),
			Summary:    summaryUnsupportedBySvcdoctor,
			Detail:     detailUnsupportedBySvcdoctor,
			// The claim names the authentication *this endpoint required*, and
			// what it required is selected by host-based rules on the connecting
			// address.
			VantageDependent: true,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendUnsupportedBySvcdoctor),
		})
	}
	return domain.Finding{}, false
}

// skippedAuthentication handles the policy refusal.
//
// It is the only finding in this package that reads a blockedBy edge, and it is
// the case the edge exists for: the claim is *why nothing was attempted*, and
// the answer lives on another node. docs/FINDINGS.md section 3.1 item 11 forbids
// citing a blocked step as a **cause**; here the blocked step is the subject and
// its blocker is the cause, which is that rule read correctly.
func skippedAuthentication(
	g domain.Graph, node domain.Evidence, refs []domain.EvidenceID,
) (domain.Finding, bool) {
	switch node.FailureClass() {
	case domain.FailureExecSkippedByPolicy:
		// Falls through to the withheld finding below.
	case domain.FailureExecRequiredInputMissing:
		// The run held nothing to present. The refs already carry the startup
		// node, which is what records that the endpoint asked — so the claim's
		// two halves are both cited without adding anything.
		return credentialNotConfigured(node, refs)
	default:
		// A skip for any other reason was caused by something earlier, and that
		// node owns the failure.
		return domain.Finding{}, false
	}

	// The blocker is what makes the claim checkable. Its absence is handled
	// rather than asserted: a finding that promised to point at the channel and
	// then did not would be worse than one that says less.
	for _, id := range g.BlockedBy(node.ID()) {
		if _, ok := g.Node(id); ok {
			refs = append(refs, id)
		}
	}

	return build(domain.FindingInput{
		Code: CodeCredentialWithheld,
		Kind: domain.FindingKindConfirmed,
		// A real problem — the channel available to this run cannot carry a
		// credential — that is not currently breaking anything, because
		// svcdoctor's own refusal prevented it.
		Severity:   domain.SeverityWarn,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerAuth,
		Subject:    node.Subject(),
		Summary:    summaryCredentialWithheld,
		Detail:     detailCredentialWithheld,
		// About svcdoctor's own policy and the channel this run established,
		// neither of which is a property of network position.
		VantageDependent: false,
		EvidenceRefs:     refs,
		Recommendations:  recommend(recommendCredentialWithheld),
	})
}

// The prose for CodeCredentialNotConfigured.
//
// "for this attempt" is load-bearing: the claim is scoped to this run against
// this endpoint, and says nothing about whether a credential exists elsewhere,
// is stored somewhere svcdoctor was not told about, or would have worked.
const (
	summaryCredentialNotConfigured = "The PostgreSQL endpoint required authentication and " +
		"this run had no credential to present"

	detailCredentialNotConfigured = "svcdoctor reached the authentication step, and the " +
		"endpoint had asked for authentication material this run was not given. Nothing was " +
		"sent: no authentication was attempted, so the endpoint neither accepted nor refused " +
		"anything, and nothing here says whether a credential would have worked.\n" +
		"The authentication this endpoint asked for is recorded on the referenced startup " +
		"node. Which methods it asks for can depend on where the connection came from, so an " +
		"endpoint that demands authentication here may not from elsewhere."

	recommendCredentialNotConfigured = "Supply a credential for this endpoint and the role " +
		"this run used, or check whether this endpoint was expected to accept the connection " +
		"without one"
)

// credentialNotConfigured builds the finding for a run that had nothing to
// present.
//
// # Why WARN and not ERROR
//
// Severity is the impact of the claim about its own subject, and this claim's
// subject is an endpoint that did nothing wrong. It answered, it asked for
// authentication, and it is not proven unhealthy by anything here. What did not
// happen is that *this run* could not continue — a real limitation, and one that
// no change to the endpoint would fix.
//
// It is the same reading CodeCredentialWithheld already carries at this step: a
// real problem that is not currently breaking anything, because svcdoctor's own
// state prevented the attempt. ERROR is deliberately not used to force a
// non-zero exit; severity and process status are different contracts.
func credentialNotConfigured(node domain.Evidence, refs []domain.EvidenceID) (domain.Finding, bool) {
	return build(domain.FindingInput{
		Code: CodeCredentialNotConfigured,
		// Nothing is left open. The node records that the step did not run for a
		// stated reason, and the startup node records that the endpoint asked.
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityWarn,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerAuth,
		Subject:    node.Subject(),
		Summary:    summaryCredentialNotConfigured,
		Detail:     detailCredentialNotConfigured,
		// The compound claim is what makes this true rather than the credential
		// half alone. That the run held nothing is not a property of network
		// position; that *this endpoint demanded authentication* is, because
		// pg_hba selects the method by source address. A claim that names both
		// inherits the weaker of the two — the same ground
		// CodeUnsupportedBySvcdoctor rests on, where a gap in svcdoctor is
		// vantage-dependent because the claim names what the endpoint required.
		VantageDependent: true,
		EvidenceRefs:     refs,
		Recommendations:  recommend(recommendCredentialNotConfigured),
	})
}

// mechanismUnavailable builds the one code whose severity varies.
//
// The claim is identical in both cases and the impact is not, which is exactly
// what Severity measures and Confidence does not. The evidence State carries the
// same distinction structurally, so severity and state agree by construction
// rather than by coincidence.
func mechanismUnavailable(
	node domain.Evidence, severity domain.Severity, action string, refs []domain.EvidenceID,
) (domain.Finding, bool) {
	return build(domain.FindingInput{
		Code:       CodeMechanismUnavailable,
		Kind:       domain.FindingKindConfirmed,
		Severity:   severity,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerAuth,
		Subject:    node.Subject(),
		Summary:    summaryMechanismUnavailable,
		Detail:     detailMechanismUnavailable,
		// Which mechanism an endpoint demands is selected by host-based rules on
		// the connecting address, so the same endpoint can demand a different
		// one of a client elsewhere.
		VantageDependent: true,
		EvidenceRefs:     refs,
		Recommendations:  recommend(action),
	})
}
