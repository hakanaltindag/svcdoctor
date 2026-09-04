package rabbitmq

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// The authentication findings.
//
// Each identifier ends in a constant naming a condition, and gosec's G101 rule
// matches on the word rather than on what the value is.
//
//nolint:gosec // G101: finding codes, not credentials.
const (
	// CodeCredentialsRejected reports that the endpoint refused the
	// authentication context it was presented.
	//
	// **It names no cause, because RabbitMQ names none.** Measured in Phase 8.0C:
	// a wrong password and an unknown user produce byte-identical Connection.Close
	// frames, and the same 403 is what a user refused by a host-based restriction
	// receives. The detailed reason is deliberately broker-side.
	CodeCredentialsRejected domain.FindingCode = "RABBITMQ_CREDENTIALS_REJECTED"

	// CodeAuthenticationNotCompleted reports that the exchange did not settle.
	//
	// Distinct from a rejection: the endpoint took no position svcdoctor could
	// read. It is also what a rejection collapses into when a client does not
	// advertise authentication_failure_close, which is why svcdoctor always does.
	CodeAuthenticationNotCompleted domain.FindingCode = "RABBITMQ_AUTHENTICATION_NOT_COMPLETED"

	// CodeAuthMechanismNotOffered reports that the endpoint does not offer PLAIN.
	CodeAuthMechanismNotOffered domain.FindingCode = "RABBITMQ_AUTH_MECHANISM_NOT_OFFERED"

	// CodeAuthenticationUnsupported reports that svcdoctor cannot perform what
	// the endpoint requires. It is a gap in the tool, not a defect in the target.
	CodeAuthenticationUnsupported domain.FindingCode = "RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR"

	// CodeCredentialNotConfigured reports that the run was given nothing to
	// present.
	CodeCredentialNotConfigured domain.FindingCode = "RABBITMQ_CREDENTIAL_NOT_CONFIGURED"

	// CodeCredentialWithheld reports that a credential existed and svcdoctor
	// refused to put it on this channel.
	CodeCredentialWithheld domain.FindingCode = "RABBITMQ_CREDENTIAL_WITHHELD"
)

const (
	summaryCredentialsRejected = "This endpoint refused the authentication context it was " +
		"presented"

	//nolint:gosec // G101: prose about a credential, containing none.
	detailCredentialsRejected = "svcdoctor authenticated with SASL PLAIN and the endpoint " +
		"answered with a refusal.\n" +
		"That is the whole of what was observed. RabbitMQ answers several different " +
		"conditions with one identical refusal and does not tell the client which one " +
		"applied; the broker's own log records the reason.\n" +
		"The credential was sent once, on this connection, and svcdoctor did not retry, " +
		"reconnect or try another mechanism."

	// detailGuestSuffix is appended only when the configured username is exactly
	// `guest`.
	//
	// **It is gated on the username and on nothing else.** RabbitMQ evaluates its
	// loopback restriction against the broker's view of the client's source
	// address, and svcdoctor can only observe its own destination address —
	// different ends of the connection. Gating on any address observation would
	// build a claim on evidence svcdoctor does not have, which is exactly why
	// Phase 8.0B dropped the hypothesis finding (ADR 0068 §4.1).
	detailGuestSuffix = "\nRabbitMQ ships with `guest` in its `loopback_users` list, so " +
		"`guest` is refused from any non-loopback source under default configuration. " +
		"svcdoctor cannot see which source address this broker observed, so it cannot tell " +
		"whether that policy applied here."

	recommendCredentialsRejected = "Check the broker's own log for the refusal reason, and " +
		"confirm the username and password against the endpoint you are diagnosing"

	summaryAuthNotCompleted = "Authentication did not complete on this endpoint"

	detailAuthNotCompleted = "svcdoctor presented a credential and the exchange did not " +
		"settle into an accepted or refused answer.\n" +
		"That is different from a refusal: the endpoint took no position svcdoctor could " +
		"read. A peer close at this point is what RabbitMQ produces for a client that did " +
		"not ask to be told about authentication failures, and svcdoctor always asks — so " +
		"this is not that case.\n" +
		"No virtual host was requested, because there was no authenticated connection to " +
		"request one on."

	recommendAuthNotCompleted = "Check the broker's log for this connection, and confirm no " +
		"proxy between svcdoctor and the broker is terminating the connection"

	summaryMechanismNotOffered = "This endpoint does not offer the SASL mechanism svcdoctor " +
		"implements"

	detailMechanismNotOffered = "The endpoint advertised its authentication mechanisms in " +
		"Connection.Start and SASL PLAIN was not among the ones svcdoctor recognizes.\n" +
		"**No credential was sent.** svcdoctor implements PLAIN only and does not fall back " +
		"to another mechanism, because a fallback ladder is how an incompatibility gets " +
		"hidden.\n" +
		"This is not a claim that the endpoint is misconfigured. It is behaving correctly " +
		"and svcdoctor is the limited party."

	recommendMechanismNotOffered = "Enable SASL PLAIN on this endpoint, or diagnose it with a " +
		"client that implements the mechanisms it offers"

	summaryAuthUnsupported = "svcdoctor could not complete the negotiation this endpoint " +
		"requires"

	detailAuthUnsupported = "The endpoint accepted the credential and then proposed " +
		"connection parameters svcdoctor's frozen contract cannot satisfy.\n" +
		"That is a limit of svcdoctor rather than a fault in the endpoint, and nothing " +
		"below this point was measured.\n" +
		"No claim is made about whether the virtual host exists or is permitted."

	recommendAuthUnsupported = "Compare the endpoint's configured frame size limit against " +
		"the AMQP 0-9-1 minimum of 4096 bytes"

	//nolint:gosec // G101: finding prose about a credential, containing none.
	summaryCredentialNotConfigured = "This run was given no credential to present"

	detailCredentialNotConfigured = "svcdoctor reached the authentication step with nothing " +
		"to authenticate with, so it presented nothing and the endpoint refused nothing.\n" +
		"**No session was established**, and the run is nonetheless complete: this is a " +
		"statement about the run's inputs rather than about the endpoint.\n" +
		"Everything measured above this point — name resolution, the connection, the " +
		"transport channel and the AMQP 0-9-1 protocol exchange — stands."

	recommendCredentialNotConfigured = "Supply --username together with --password-file or " +
		"--password-stdin to diagnose authentication and virtual host access"

	summaryCredentialWithheld = "svcdoctor refused to send the credential over this channel"

	detailCredentialWithheld = "A credential was configured and svcdoctor did not put it on " +
		"the wire, because the channel's peer identity was not verified.\n" +
		"**Zero credential bytes were sent.** A plaintext connection and a connection with " +
		"--tls-insecure are both refused, and neither a loopback address nor a private one " +
		"changes that.\n" +
		"Everything above this point was still measured, including the endpoint's own " +
		"product, version and offered authentication mechanisms."

	recommendCredentialWithheld = "Use --tls require with a trusted certificate chain, or " +
		"supply --tls-ca-file so the endpoint's identity can be verified"
)

// Authentication owns every outcome the credential step can produce.
//
// It is a diagnosis.Rule. It keys on the node's state and failure class, both of
// which the adapter committed to, and never on a peer's text.
func Authentication(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, node := range nodesAt(g, servicerabbitmq.StepAuthentication) {
		in, ok := authenticationFinding(node)
		if !ok {
			continue
		}
		in.Subject = node.Subject()
		in.EvidenceRefs = []domain.EvidenceID{node.ID()}
		finding, built := build(in)
		if !built {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// authenticationFinding maps one node to the finding it owns, if any.
func authenticationFinding(node domain.Evidence) (domain.FindingInput, bool) {
	switch node.State() {
	case domain.StateSkipped:
		switch node.FailureClass() {
		case domain.FailureExecRequiredInputMissing:
			return domain.FindingInput{
				Code:     CodeCredentialNotConfigured,
				Kind:     domain.FindingKindConfirmed,
				Severity: domain.SeverityWarn,
				// Direct evidence: the run's own inputs, not an inference.
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Summary:          summaryCredentialNotConfigured,
				Detail:           detailCredentialNotConfigured,
				VantageDependent: false,
				Recommendations:  recommend(recommendCredentialNotConfigured),
			}, true
		case domain.FailureExecSkippedByPolicy:
			return domain.FindingInput{
				Code:             CodeCredentialWithheld,
				Kind:             domain.FindingKindConfirmed,
				Severity:         domain.SeverityWarn,
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Summary:          summaryCredentialWithheld,
				Detail:           detailCredentialWithheld,
				VantageDependent: false,
				Recommendations:  recommend(recommendCredentialWithheld),
			}, true
		}

	case domain.StateUnknown:
		switch node.FailureClass() {
		case domain.FailureAuthMechanismNotOffered:
			return domain.FindingInput{
				Code:             CodeAuthMechanismNotOffered,
				Kind:             domain.FindingKindConfirmed,
				Severity:         domain.SeverityError,
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Summary:          summaryMechanismNotOffered,
				Detail:           detailMechanismNotOffered,
				VantageDependent: false,
				Recommendations:  recommend(recommendMechanismNotOffered),
			}, true
		case domain.FailureProtocolUnsupportedCapability:
			return domain.FindingInput{
				Code:             CodeAuthenticationUnsupported,
				Kind:             domain.FindingKindConfirmed,
				Severity:         domain.SeverityWarn,
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Summary:          summaryAuthUnsupported,
				Detail:           detailAuthUnsupported,
				VantageDependent: false,
				Recommendations:  recommend(recommendAuthUnsupported),
			}, true
		}
		// Every other UNKNOWN is svcdoctor's own budget or cancellation, which
		// the run reports as incompleteness rather than as a target failure.

	case domain.StateFail:
		if node.FailureClass() == domain.FailureAuthCredentialsRejected {
			return domain.FindingInput{
				Code:     CodeCredentialsRejected,
				Kind:     domain.FindingKindConfirmed,
				Severity: domain.SeverityError,
				// The endpoint took a position. What it did not do is say why,
				// and neither does this finding.
				Confidence: domain.ConfidenceHigh,
				Layer:      domain.LayerAuth,
				Summary:    summaryCredentialsRejected,
				Detail:     credentialsRejectedDetail(node),
				// A host-based restriction is one of the conditions this refusal
				// covers, and that one is source-keyed.
				VantageDependent: true,
				Recommendations:  recommend(recommendCredentialsRejected),
			}, true
		}
		return domain.FindingInput{
			Code:             CodeAuthenticationNotCompleted,
			Kind:             domain.FindingKindConfirmed,
			Severity:         domain.SeverityError,
			Confidence:       domain.ConfidenceHigh,
			Layer:            domain.LayerAuth,
			Summary:          summaryAuthNotCompleted,
			Detail:           detailAuthNotCompleted,
			VantageDependent: true,
			Recommendations:  recommend(recommendAuthNotCompleted),
		}, true
	}

	return domain.FindingInput{}, false
}

// credentialsRejectedDetail appends the `guest` sentence when, and only when,
// the run's own username was exactly `guest`.
//
// The username is read from the node's identity attribute, which the adapter
// recorded from the run's input rather than from anything the peer said.
func credentialsRejectedDetail(node domain.Evidence) string {
	if identity, ok := identityAttr(node, servicerabbitmq.AttrIdentity); ok && identity == "guest" {
		return detailCredentialsRejected + detailGuestSuffix
	}
	return detailCredentialsRejected
}
