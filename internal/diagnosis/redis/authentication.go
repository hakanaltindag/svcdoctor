package redis

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// CodeCredentialsRejected reports that the endpoint refused the credential
// svcdoctor presented.
//
// # It names no cause, because Redis names none
//
// `-WRONGPASS invalid username-password pair or user is disabled.` is a single
// reply site (redis/src/acl.c:1511) covering an unknown user, a wrong password
// and a disabled user. The server distinguishes them internally as ENOENT versus
// EINVAL and discards the distinction before building the reply. Any wording
// here that said "wrong password" would be picking one of three possibilities
// and presenting it as the answer.
// names what svcdoctor concluded about a credential; it holds none.
//
//nolint:gosec // G101: a finding code, not a credential. The identifier
const CodeCredentialsRejected domain.FindingCode = "REDIS_CREDENTIALS_REJECTED"

// CodeAuthenticationNotCompleted is the L5 floor: the authentication exchange
// did not settle.
const CodeAuthenticationNotCompleted domain.FindingCode = "REDIS_AUTHENTICATION_NOT_COMPLETED"

// CodeCredentialWithheld reports that svcdoctor refused to put the credential on
// this channel.
//
// **Nothing was sent.** The endpoint expressed no opinion, and this finding must
// never read as one: it is a statement about svcdoctor's own transport policy,
// which requires a channel whose peer identity was verified. Neither a loopback
// address nor a private one changes that (ADR 0064 section 7).
// names what svcdoctor concluded about a credential; it holds none.
//
//nolint:gosec // G101: a finding code, not a credential. The identifier
const CodeCredentialWithheld domain.FindingCode = "REDIS_CREDENTIAL_WITHHELD"

// CodeCredentialNotConfigured reports an endpoint that demands authentication on
// a run that carries none.
//
// # It is WARN and the run is complete
//
// This is the shape ADR 0046 and ADR 0048 section 9 froze for PostgreSQL and it
// binds here unchanged: status OK, `Result.Incomplete()` false, exit code 0, and
// **no usability proof**. A renderer must show all three of those facts
// separately, because "svcdoctor was not given a credential" is not a defect in
// the endpoint and not a successful diagnosis of one.
// names what svcdoctor concluded about a credential; it holds none.
//
//nolint:gosec // G101: a finding code, not a credential. The identifier
const CodeCredentialNotConfigured domain.FindingCode = "REDIS_CREDENTIAL_NOT_CONFIGURED"

// string in this block is operator-facing text; the secret never reaches this
// package, which internal/diagnosis cannot even import.
//
//nolint:gosec // G101: finding prose about a credential, containing none. Every
const (
	summaryCredentialsRejected = "The endpoint rejected the credential svcdoctor presented"

	detailCredentialsRejected = "The endpoint answered the authentication command with " +
		"WRONGPASS.\n" +
		"Redis and Valkey return that single condition for an unknown user, an incorrect " +
		"password and a disabled user alike, and discard the distinction before replying, so " +
		"svcdoctor cannot tell which of the three occurred and does not guess.\n" +
		"A successful authentication would also not have proved the credential correct: a user " +
		"configured with nopass accepts every password."

	recommendCredentialsRejected = "Check the username and secret this run used against the " +
		"endpoint's ACL configuration, and check the endpoint's ACL log for the attempt"

	summaryAuthenticationNotCompleted = "The authentication exchange did not complete at this " +
		"endpoint, so svcdoctor learned nothing about the credential"

	detailAuthenticationNotCompleted = "The authentication command was sent and the exchange " +
		"ended without the endpoint taking a position on the credential.\n" +
		"This is not a rejection: the endpoint neither accepted nor refused what was presented."

	recommendAuthenticationNotCompleted = "Review the endpoint's connection-level logs for this " +
		"vantage's address around the time of this run"

	summaryCredentialWithheld = "svcdoctor did not send the credential, because the channel to " +
		"this endpoint did not satisfy its credential-transport policy"

	detailCredentialWithheld = "Zero credential bytes were written. The endpoint expressed no " +
		"opinion about the credential and this finding is not one.\n" +
		"svcdoctor presents a credential only over a channel whose peer identity was verified. " +
		"A plaintext connection, and a TLS connection with verification disabled, are both " +
		"refused; a loopback or private address grants no exemption, because an address says " +
		"nothing about the path the bytes take."

	recommendCredentialWithheld = "Enable TLS for this endpoint and supply the trust material " +
		"that verifies it, then run again"

	summaryCredentialNotConfigured = "This endpoint requires authentication and this run was " +
		"given no credential, so usability was not measured"

	detailCredentialNotConfigured = "The endpoint refused the credential-free capability " +
		"command until the connection is authenticated, which is how svcdoctor knows a " +
		"credential is required here.\n" +
		"Nothing about the endpoint is wrong, and nothing about it is confirmed working " +
		"either: no usability probe was run."

	recommendCredentialNotConfigured = "Supply the credential your application uses for this " +
		"endpoint and run again"
)

// Authentication reports what happened at the credential boundary.
//
// It is a diagnosis.Rule. One finding per authentication node at most, chosen on
// state and failure class so that the four outcomes are disjoint by construction
// and no node can produce two.
func Authentication(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, node := range nodesAt(g, serviceredis.StepAuthentication) {
		finding, ok := evaluateAuthentication(node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func evaluateAuthentication(node domain.Evidence) (domain.Finding, bool) {
	refs := []domain.EvidenceID{node.ID()}

	switch node.State() {
	case domain.StateSkipped:
		switch node.FailureClass() {
		case domain.FailureExecSkippedByPolicy:
			return build(domain.FindingInput{
				Code: CodeCredentialWithheld,
				Kind: domain.FindingKindConfirmed,
				// It stops the run from answering the question it was asked, and
				// it is svcdoctor's own decision rather than a target defect.
				Severity:   domain.SeverityWarn,
				Confidence: domain.ConfidenceHigh,
				Layer:      domain.LayerAuth,
				Subject:    node.Subject(),
				Summary:    summaryCredentialWithheld,
				Detail:     detailCredentialWithheld,
				// The policy decision depends on the channel this run
				// established, which depends on where it ran and what it was
				// configured with.
				VantageDependent: true,
				EvidenceRefs:     refs,
				Recommendations:  recommend(recommendCredentialWithheld),
			})
		case domain.FailureExecRequiredInputMissing:
			return build(domain.FindingInput{
				Code:             CodeCredentialNotConfigured,
				Kind:             domain.FindingKindConfirmed,
				Severity:         domain.SeverityWarn,
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Subject:          node.Subject(),
				Summary:          summaryCredentialNotConfigured,
				Detail:           detailCredentialNotConfigured,
				VantageDependent: false,
				EvidenceRefs:     refs,
				Recommendations:  recommend(recommendCredentialNotConfigured),
			})
		}
		return domain.Finding{}, false

	case domain.StateFail:
		if node.FailureClass() == domain.FailureAuthCredentialsRejected {
			return build(domain.FindingInput{
				Code:       CodeCredentialsRejected,
				Kind:       domain.FindingKindConfirmed,
				Severity:   domain.SeverityError,
				Confidence: domain.ConfidenceHigh,
				Layer:      domain.LayerAuth,
				Subject:    node.Subject(),
				Summary:    summaryCredentialsRejected,
				Detail:     detailCredentialsRejected,
				// ACL rules can be scoped by source, so a credential refused
				// from here is not proved refused from everywhere.
				VantageDependent: true,
				EvidenceRefs:     refs,
				Recommendations:  recommend(recommendCredentialsRejected),
			})
		}
		return build(domain.FindingInput{
			Code:             CodeAuthenticationNotCompleted,
			Kind:             domain.FindingKindConfirmed,
			Severity:         domain.SeverityError,
			Confidence:       domain.ConfidenceHigh,
			Layer:            domain.LayerAuth,
			Subject:          node.Subject(),
			Summary:          summaryAuthenticationNotCompleted,
			Detail:           detailAuthenticationNotCompleted,
			VantageDependent: true,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendAuthenticationNotCompleted),
		})
	}

	// PASS produces nothing, and UNKNOWN produces nothing: an UNKNOWN
	// authentication is svcdoctor's own budget or its own reply ceiling, and the
	// report's incompleteness already reports that.
	return domain.Finding{}, false
}
