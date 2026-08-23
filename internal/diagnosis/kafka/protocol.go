package kafka

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The ten codes the Kafka protocol stages can produce.
//
// # Why these exist at all
//
// Phase 6.1c was stopped by ADR 0054. `internal/diagnosis/kafka` owned only the
// two advertised-broker findings, so every protocol outcome — including a
// rejected credential — would have reached a report as `findings: []`,
// `status: OK`, exit 0 the moment a composition root existed. `deriveSummary`
// takes its status from findings alone, and `incompleteRun` covers only
// `UNKNOWN` with `EXEC_LOCAL_TIMEOUT` or `EXEC_CANCELLED`. Nothing else would
// have spoken.
//
// # Why ten and not one, and not twenty
//
// docs/FINDINGS.md section 3.1 item 11 gives the test for a merge: two outcomes
// share a code when the reader's first move is the same. Applied here it
// separates the specific claims from three per-stage floors, and it is also what
// stops the floors from swallowing the specific claims — the failure ADR 0044
// and ADR 0053 both had to refuse.
//
// Each stage keeps its own floor rather than sharing one. "The exchange did not
// complete" is a different sentence at L4, L5 and L6: it means *this may not be
// a Kafka broker*, *the negotiation broke down*, and *the cluster answered
// nothing about itself*. One shared floor would force the vaguest of the three
// onto all of them.
//
// # None mirrors a FailureClass
//
// A report carries `failureClass` on the evidence node and `code` on the
// finding. The `KAFKA_` prefix keeps the two namespaces apart, as `POSTGRES_`
// does — which is the licence the generic `TLS_*` codes in
// internal/diagnosis/transport deliberately do not have.
const (
	// CodeAPIVersionsVersionRejected: the endpoint answered the capability
	// exchange, and refused the request version it was sent.
	//
	// **The endpoint is Kafka and it is talking.** That is what separates this
	// from the floor beside it, and it is the whole value of the code: the next
	// move is about version compatibility, not about whether the port is right.
	CodeAPIVersionsVersionRejected domain.FindingCode = "KAFKA_API_VERSIONS_VERSION_REJECTED"

	// CodeAPIVersionsNotCompleted is the L4 floor: the capability exchange was
	// attempted and did not complete.
	//
	// **It attributes no cause.** It does not say the endpoint is not Kafka,
	// that the port is wrong, that a proxy interfered or that the broker is too
	// old. Each of those is a cause, and this is an observation.
	CodeAPIVersionsNotCompleted domain.FindingCode = "KAFKA_API_VERSIONS_NOT_COMPLETED"

	// CodeAuthMechanismNotOffered: the endpoint did not offer the SASL mechanism
	// this run named.
	//
	// A peer fact, and the opposite direction from
	// CodeAuthenticationUnsupportedBySvcdoctor. Here the endpoint declines what
	// svcdoctor speaks; there svcdoctor cannot speak what the endpoint offered.
	// The two lead to opposite next moves and ADR 0030 keeps them apart.
	CodeAuthMechanismNotOffered domain.FindingCode = "KAFKA_AUTH_MECHANISM_NOT_OFFERED"

	// CodeSASLHandshakeNotCompleted is the L5 negotiation floor.
	CodeSASLHandshakeNotCompleted domain.FindingCode = "KAFKA_SASL_HANDSHAKE_NOT_COMPLETED"

	// CodeCredentialsRejected: the endpoint evaluated the credential it was
	// presented and refused it.
	//
	// **A refusal, never a cause.** Kafka answers with one error code for a
	// wrong secret, an unknown principal, a disabled or locked account and a
	// failing authentication backend, and its error message is deliberately
	// generic so a client cannot tell which. The prose says "rejected" and stops.
	//nolint:gosec // G101: a public finding code, not a credential. The rule
	// fires on the identifier containing "Credentials"; this constant is the
	// name of a claim that appears in every report.
	CodeCredentialsRejected domain.FindingCode = "KAFKA_CREDENTIALS_REJECTED"

	// CodeAuthenticationUnsupportedBySvcdoctor: the endpoint negotiated a
	// mechanism svcdoctor does not perform.
	//
	// The gap is svcdoctor's. INFO, and never a claim that the endpoint lacks
	// something.
	CodeAuthenticationUnsupportedBySvcdoctor domain.FindingCode = "KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR"

	// CodePeerVerificationFailed: the broker did not prove it knows the
	// credential.
	//
	// SCRAM authenticates **both** parties, so an authentication failure has a
	// direction and the two directions are different claims. This is the one
	// where svcdoctor refuses the peer: the broker accepted the client proof and
	// then presented a server signature that did not verify.
	//
	// It is deliberately not CodeCredentialsRejected, which says the opposite —
	// that the endpoint refused svcdoctor's material. Normalizing the two
	// together was the PostgreSQL adapter's own defect until Phase 4.6a.5 (ADR
	// 0038 amendment D), and this mirrors the correction rather than repeating
	// the mistake in a second service.
	//
	// Unreachable before Phase 6.2: PLAIN authenticates one party, so there was
	// no peer proof to fail. SCRAM-SHA-256 made it reachable, and ADR 0054
	// requires the owner to arrive with the producer rather than after it.
	CodePeerVerificationFailed domain.FindingCode = "KAFKA_PEER_VERIFICATION_FAILED"

	// CodeCredentialWithheld: a credential was configured and svcdoctor declined
	// to present it over the channel this path established.
	//
	// This is svcdoctor's own security decision (ADR 0029), and it must be
	// visible. A refusal nobody can see reads as a run that simply did not
	// authenticate.
	//nolint:gosec // G101: a public finding code, not a credential. See
	// CodeCredentialsRejected.
	CodeCredentialWithheld domain.FindingCode = "KAFKA_CREDENTIAL_WITHHELD"

	// CodeCredentialNotConfigured: the endpoint required an authentication
	// svcdoctor can perform, and this run had nothing to present.
	//
	// The producer is Phase 6.1c-P1's; this is the owner ADR 0054 required
	// before it could become production-reachable.
	//nolint:gosec // G101: a public finding code, not a credential. It is the
	// reverse of a secret — it names the absence of one.
	CodeCredentialNotConfigured domain.FindingCode = "KAFKA_CREDENTIAL_NOT_CONFIGURED"

	// CodeAuthenticationNotCompleted is the L5 authentication floor.
	//
	// **It does not imply a credential was refused.** That is
	// CodeCredentialsRejected, and conflating the two would accuse a credential
	// no endpoint evaluated.
	CodeAuthenticationNotCompleted domain.FindingCode = "KAFKA_AUTHENTICATION_NOT_COMPLETED"

	// CodeMetadataNotCompleted is the L6 floor: the Metadata exchange did not
	// complete at this endpoint.
	//
	// **Scoped to this exchange.** svcdoctor sends Metadata v1 with an empty
	// topic list, so a failure says nothing about topics, partitions, the
	// controller, or whether the cluster is healthy — none of which was asked
	// about. ADR 0052 forbids the report saying "cluster usable" on success, and
	// the same discipline forbids "cluster broken" here.
	CodeMetadataNotCompleted domain.FindingCode = "KAFKA_METADATA_NOT_COMPLETED"
)

// The prose. One summary, one detail and one recommendation per code.
//
// No recommendation is executable: svcdoctor suggests where to look, never what
// to run.
const (
	summaryVersionRejected = "The Kafka endpoint refused the ApiVersions request version " +
		"svcdoctor sent"
	detailVersionRejected = "The endpoint answered the capability exchange and returned " +
		"UNSUPPORTED_VERSION, so it is speaking the Kafka protocol and declined this " +
		"particular request version.\n" +
		"This states what the endpoint refused, not that the broker is too old, " +
		"misconfigured, or unusable by other clients."
	recommendVersionRejected = "Check the broker version against the ApiVersions request " +
		"version recorded on the evidence node"

	summaryAPIVersionsNotCompleted = "The Kafka ApiVersions exchange did not complete at this " +
		"endpoint"
	detailAPIVersionsNotCompleted = "A connection was established and the capability exchange " +
		"was attempted, and it did not complete.\n" +
		"svcdoctor could not attribute why. This does not state that the endpoint is not " +
		"Kafka, that the port is wrong, or that anything on the path interfered."
	recommendAPIVersionsNotCompleted = "Check what is listening on this address and port, and " +
		"whether anything on the path terminates or rewrites the connection"

	summaryMechanismNotOffered = "The Kafka endpoint did not offer the SASL mechanism this run " +
		"asked for"
	detailMechanismNotOffered = "The endpoint answered the handshake and reported that the " +
		"named mechanism is not one it offers.\n" +
		"Kafka enables SASL mechanisms per listener, so this describes the listener reached " +
		"at this address and port."
	recommendMechanismNotOffered = "Check sasl.enabled.mechanisms on the listener serving this " +
		"address and port, and which mechanism this run was configured to use"

	summaryHandshakeNotCompleted = "The Kafka SASL handshake did not complete at this endpoint"
	detailHandshakeNotCompleted  = "Mechanism negotiation was attempted and did not complete.\n" +
		"svcdoctor could not attribute why, and no authentication was attempted afterwards."
	recommendHandshakeNotCompleted = "Check the broker log for this connection, and whether " +
		"the listener expects SASL at all"

	summaryPeerVerificationFailed = "The Kafka broker failed authentication proof verification"
	detailPeerVerificationFailed  = "SCRAM authenticates both parties. " +
		"The broker accepted the material svcdoctor presented, and then presented a value of " +
		"its own that did not verify against the configured credential.\n" +
		"The observation does not say why: a broker that does not hold this credential, " +
		"something answering in its place, and a defective implementation are indistinguishable " +
		"from what was exchanged."
	recommendPeerVerificationFailed = "Verify the credential configured for this endpoint, and " +
		"establish what this broker is before presenting the credential again"

	//nolint:gosec // G101: report prose, not a credential.
	summaryCredentialsRejected = "The Kafka endpoint rejected the credential it was presented"
	detailCredentialsRejected  = "Authentication completed and the endpoint refused the " +
		"material it was shown.\n" +
		"Kafka returns one error code for a wrong secret, an unknown principal, a disabled " +
		"account and a failing authentication backend alike, so this states that the " +
		"credential was refused and not why."
	recommendCredentialsRejected = "Check the principal and secret this run was configured " +
		"with, and the broker's authentication backend for this listener"

	summaryUnsupportedBySvcdoctor = "svcdoctor cannot perform the SASL mechanism this Kafka " +
		"endpoint negotiated"
	detailUnsupportedBySvcdoctor = "The endpoint agreed to a mechanism svcdoctor does not " +
		"implement, so nothing was presented and no byte of credential material was sent.\n" +
		"This is a gap in svcdoctor, not a defect in the endpoint. Whether the credential " +
		"would have been accepted is unknown."
	recommendUnsupportedBySvcdoctor = "Check whether the listener offers a mechanism svcdoctor " +
		"supports, or verify this endpoint with a Kafka client that implements the negotiated one"

	summaryCredentialWithheld = "svcdoctor did not present the configured Kafka credential " +
		"over this channel"
	detailCredentialWithheld = "A credential was configured and the endpoint asked for " +
		"authentication, and svcdoctor declined to send it because the channel this path " +
		"established did not satisfy the credential-transport policy.\n" +
		"No credential material was written. This is svcdoctor's own refusal, not an " +
		"observation of the endpoint."
	recommendCredentialWithheld = "Establish verified TLS to this endpoint, or review the " +
		"trust context this run used, then re-run"

	summaryCredentialNotConfigured = "The Kafka endpoint required authentication and this run " +
		"had no credential configured"
	detailCredentialNotConfigured = "svcdoctor reached authentication, the endpoint negotiated " +
		"a mechanism svcdoctor can perform, and the run held nothing to present.\n" +
		"Nothing was sent and nothing was refused. No change to the endpoint would resolve " +
		"this; the missing input is this run's."
	recommendCredentialNotConfigured = "Supply a credential for this endpoint and the " +
		"mechanism the listener offers, then re-run"

	summaryAuthenticationNotCompleted = "The Kafka authentication exchange did not complete at " +
		"this endpoint"
	detailAuthenticationNotCompleted = "Authentication was attempted and the exchange did not " +
		"complete.\n" +
		"svcdoctor could not attribute why. This does not state that a credential was " +
		"evaluated or refused."
	recommendAuthenticationNotCompleted = "Check the broker log for this connection around the " +
		"time recorded on the evidence node"

	summaryMetadataNotCompleted = "The Kafka Metadata exchange did not complete at this endpoint"
	detailMetadataNotCompleted  = "The cluster was asked to describe itself and the exchange " +
		"did not complete, so no broker topology was obtained from this endpoint.\n" +
		"svcdoctor requests Metadata with an empty topic list, so this says nothing about " +
		"topics, partitions, the controller, or whether the cluster is healthy."
	recommendMetadataNotCompleted = "Check the broker log for this connection, and whether the " +
		"authenticated principal may describe the cluster"
)

// claim is what one authorized outcome supports.
type claim struct {
	code           domain.FindingCode
	severity       domain.Severity
	summary        string
	detail         string
	recommendation string

	// vantageDependent is decided per claim rather than shared.
	//
	// The repository has both answers already — internal/diagnosis/transport
	// sets it true for every code it produces, internal/diagnosis/postgres
	// varies it per finding — and copying either wholesale is what ADR 0012
	// warns against. The reasoning for each value is on its table entry.
	vantageDependent bool
}

// outcome is the closed key: a step, a state and a failure class together.
//
// **State is part of the key deliberately.** It is what makes "a class that
// matches while the state does not" produce nothing, without a separate guard
// that could be forgotten — a `SKIPPED` node carrying `AUTH_CREDENTIALS_REJECTED`
// is a shape this rule declines to read rather than one it guesses at.
type outcome struct {
	step    domain.Step
	state   domain.State
	failure domain.FailureClass
}

// protocolClaims maps every authorized Kafka protocol outcome onto its claim.
//
// # Closed, with no default branch
//
// A key absent from this table produces no finding, including one a later phase
// adds to the domain. A `default` folding the unrecognized into a floor would
// silently grant a new producer a claim nobody reviewed, and the floors' own
// wording — "could not attribute why" — would become a statement about a class
// that may be perfectly attributable. This is the rule ADR 0053 fixed for TLS,
// applied to a wider surface.
//
// # What is deliberately absent
//
// **`UNKNOWN` with `EXEC_LOCAL_TIMEOUT` or `EXEC_CANCELLED`, at every step.**
// svcdoctor's own budget ended the measurement, and nothing was learned about
// the endpoint. Turning either into a claim is the local-timeout-as-remote-
// failure mistake the whole claim discipline exists to prevent. Those outcomes
// reach the operator through `Result.Incomplete()` and exit code 4, never
// through a finding here.
//
// **Every `PASS`.** ADR 0052 fixes the success vocabulary as a renderer concern:
// `kafka.metadata` passing means *Kafka metadata obtained*, and no finding
// asserts it. A success finding would also make the advertised-broker rules
// ambiguous about what they add.
//
// **`PROTOCOL_UNSUPPORTED_VERSION` at `kafka.metadata`.** Verified against
// internal/adapter/kafka/metadata.go rather than assumed: its classify consults
// no broker error code, because Metadata carries a top-level one only from v13
// and svcdoctor sends v1. Writing the mapping would authorize a claim for
// evidence that cannot occur.
//
// # Two entries share a code across two steps
//
// `AUTH_MECHANISM_NOT_OFFERED` is reachable at `kafka.sasl_authenticate` as well
// as at `kafka.sasl_handshake`, because authenticationFailure falls through to
// handshakeFailure for any code it does not itself translate. The claim — *this
// endpoint did not offer the mechanism that was named* — is equally true
// wherever the endpoint said it, so both map to the same code rather than the
// later one falling into the authentication floor and losing the specific fact.
var protocolClaims = map[outcome]claim{
	// --- L4 capability discovery ------------------------------------------
	{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolUnsupportedVersion}: {
		code:     CodeAPIVersionsVersionRejected,
		severity: domain.SeverityError,
		// Which protocol versions a broker implements is a property of the
		// binary answering at this address. Kafka keys it on nothing about the
		// client, so a second observer reaching the same address is told the
		// same thing.
		vantageDependent: false,
		summary:          summaryVersionRejected,
		detail:           detailVersionRejected,
		recommendation:   recommendVersionRejected,
	},
	{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolUnexpectedResponse}: {
		code:     CodeAPIVersionsNotCompleted,
		severity: domain.SeverityError,
		// A floor attributes no cause and therefore cannot exclude a
		// path-keyed one: something present on one route and absent from
		// another can answer in the endpoint's place.
		vantageDependent: true,
		summary:          summaryAPIVersionsNotCompleted,
		detail:           detailAPIVersionsNotCompleted,
		recommendation:   recommendAPIVersionsNotCompleted,
	},
	{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolMalformedResponse}: {
		code:             CodeAPIVersionsNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryAPIVersionsNotCompleted,
		detail:           detailAPIVersionsNotCompleted,
		recommendation:   recommendAPIVersionsNotCompleted,
	},
	{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolPeerClosed}: {
		code:             CodeAPIVersionsNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryAPIVersionsNotCompleted,
		detail:           detailAPIVersionsNotCompleted,
		recommendation:   recommendAPIVersionsNotCompleted,
	},

	// --- L5 mechanism negotiation -----------------------------------------
	{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureAuthMechanismNotOffered}: {
		code:     CodeAuthMechanismNotOffered,
		severity: domain.SeverityError,
		// **This is where Kafka and PostgreSQL genuinely differ, and the
		// difference is not cosmetic.** internal/diagnosis/postgres sets true on
		// the comparable claim because pg_hba selects the method by *source
		// address*, so what the endpoint required is partly a fact about who
		// asked. Kafka has no such rule: sasl.enabled.mechanisms is configured
		// per listener, and one address and port is one listener. A second
		// observer reaching this address is offered the same set.
		vantageDependent: false,
		summary:          summaryMechanismNotOffered,
		detail:           detailMechanismNotOffered,
		recommendation:   recommendMechanismNotOffered,
	},
	{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolUnsupportedVersion}: {
		code:             CodeSASLHandshakeNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryHandshakeNotCompleted,
		detail:           detailHandshakeNotCompleted,
		recommendation:   recommendHandshakeNotCompleted,
	},
	{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolUnexpectedResponse}: {
		code:             CodeSASLHandshakeNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryHandshakeNotCompleted,
		detail:           detailHandshakeNotCompleted,
		recommendation:   recommendHandshakeNotCompleted,
	},
	{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolMalformedResponse}: {
		code:             CodeSASLHandshakeNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryHandshakeNotCompleted,
		detail:           detailHandshakeNotCompleted,
		recommendation:   recommendHandshakeNotCompleted,
	},
	{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolPeerClosed}: {
		code:             CodeSASLHandshakeNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryHandshakeNotCompleted,
		detail:           detailHandshakeNotCompleted,
		recommendation:   recommendHandshakeNotCompleted,
	},

	// --- L5 authentication -------------------------------------------------
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureAuthCredentialsRejected}: {
		code:     CodeCredentialsRejected,
		severity: domain.SeverityError,
		// A completed evaluation: the endpoint was shown material and refused
		// it. That record does not become false when a different observer is
		// treated differently. This matches internal/diagnosis/postgres on the
		// same fact, and for the same reason rather than by imitation.
		vantageDependent: false,
		summary:          summaryCredentialsRejected,
		detail:           detailCredentialsRejected,
		recommendation:   recommendCredentialsRejected,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureAuthPeerVerificationFailed}: {
		code:     CodePeerVerificationFailed,
		severity: domain.SeverityError,
		// A completed evaluation, like a rejection: this broker presented a
		// signature and it did not verify. That does not become false because a
		// different observer is treated differently.
		vantageDependent: false,
		summary:          summaryPeerVerificationFailed,
		detail:           detailPeerVerificationFailed,
		recommendation:   recommendPeerVerificationFailed,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor}: {
		// The same claim CodeAuthenticationUnsupportedBySvcdoctor already makes
		// — *svcdoctor could not perform this* — reached by a different route:
		// an identity or password outside the printable-ASCII range svcdoctor
		// can prepare for SCRAM, an iteration count above the ceiling, or a
		// local derivation fault.
		//
		// It reuses that code rather than adding a second one, because a
		// separate code would divide one operator-facing fact into two on the
		// basis of which internal check produced it.
		code:             CodeAuthenticationUnsupportedBySvcdoctor,
		severity:         domain.SeverityInfo,
		vantageDependent: false,
		summary:          summaryUnsupportedBySvcdoctor,
		detail:           detailUnsupportedBySvcdoctor,
		recommendation:   recommendUnsupportedBySvcdoctor,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureAuthMechanismNotOffered}: {
		code:             CodeAuthMechanismNotOffered,
		severity:         domain.SeverityError,
		vantageDependent: false,
		summary:          summaryMechanismNotOffered,
		detail:           detailMechanismNotOffered,
		recommendation:   recommendMechanismNotOffered,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolUnsupportedVersion}: {
		code:             CodeAuthenticationNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryAuthenticationNotCompleted,
		detail:           detailAuthenticationNotCompleted,
		recommendation:   recommendAuthenticationNotCompleted,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolUnexpectedResponse}: {
		code:             CodeAuthenticationNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryAuthenticationNotCompleted,
		detail:           detailAuthenticationNotCompleted,
		recommendation:   recommendAuthenticationNotCompleted,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolMalformedResponse}: {
		code:             CodeAuthenticationNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryAuthenticationNotCompleted,
		detail:           detailAuthenticationNotCompleted,
		recommendation:   recommendAuthenticationNotCompleted,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolPeerClosed}: {
		code:             CodeAuthenticationNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryAuthenticationNotCompleted,
		detail:           detailAuthenticationNotCompleted,
		recommendation:   recommendAuthenticationNotCompleted,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateUnknown, domain.FailureAuthMechanismUnsupported}: {
		code: CodeAuthenticationUnsupportedBySvcdoctor,
		// INFO, because the claim is about svcdoctor. §12 of
		// docs/ARCHITECTURE.md requires that an unsupported capability is a gap
		// in the tool rather than a defect in the target, and severity measures
		// the impact of the claim. ERROR would report svcdoctor's own limit as a
		// target-side problem and take the exit code with it.
		severity: domain.SeverityInfo,
		// The claim names what svcdoctor cannot do. Which mechanism was
		// negotiated is a listener property, and svcdoctor's capability is a
		// property of this binary; neither is keyed on network position.
		vantageDependent: false,
		summary:          summaryUnsupportedBySvcdoctor,
		detail:           detailUnsupportedBySvcdoctor,
		recommendation:   recommendUnsupportedBySvcdoctor,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateSkipped, domain.FailureExecSkippedByPolicy}: {
		code: CodeCredentialWithheld,
		// A real problem that is not currently breaking use of the endpoint:
		// svcdoctor's own state prevented the attempt. WARN is not chosen to
		// reach exit 0 — severity and process status are different contracts —
		// but because nothing about the target was proven wrong.
		severity: domain.SeverityWarn,
		// The claim names the channel *this path established*, and whether a
		// handshake verified depends on this run's trust context and on what
		// sits between here and the endpoint. Both are properties of network
		// position.
		vantageDependent: true,
		summary:          summaryCredentialWithheld,
		detail:           detailCredentialWithheld,
		recommendation:   recommendCredentialWithheld,
	},
	{servicekafka.StepSASLAuthenticate, domain.StateSkipped, domain.FailureExecRequiredInputMissing}: {
		code:     CodeCredentialNotConfigured,
		severity: domain.SeverityWarn,
		// **Decided here rather than inherited.** internal/diagnosis/postgres
		// sets true on its equivalent, reasoning that the compound claim names
		// what *the endpoint required* and pg_hba selects that by source
		// address, so the claim inherits the weaker half. Kafka's half is not
		// weak: a listener's SASL requirement is fixed per listener, and one
		// address and port is one listener. The other half — that this run held
		// nothing — is svcdoctor's own configuration and is not a fact about
		// network position at all. Neither half is source-keyed, so the compound
		// claim is not either.
		vantageDependent: false,
		summary:          summaryCredentialNotConfigured,
		detail:           detailCredentialNotConfigured,
		recommendation:   recommendCredentialNotConfigured,
	},

	// --- L6 topology discovery ---------------------------------------------
	{servicekafka.StepMetadata, domain.StateFail, domain.FailureProtocolUnexpectedResponse}: {
		code:             CodeMetadataNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryMetadataNotCompleted,
		detail:           detailMetadataNotCompleted,
		recommendation:   recommendMetadataNotCompleted,
	},
	{servicekafka.StepMetadata, domain.StateFail, domain.FailureProtocolMalformedResponse}: {
		code:             CodeMetadataNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryMetadataNotCompleted,
		detail:           detailMetadataNotCompleted,
		recommendation:   recommendMetadataNotCompleted,
	},
	{servicekafka.StepMetadata, domain.StateFail, domain.FailureProtocolPeerClosed}: {
		code:             CodeMetadataNotCompleted,
		severity:         domain.SeverityError,
		vantageDependent: true,
		summary:          summaryMetadataNotCompleted,
		detail:           detailMetadataNotCompleted,
		recommendation:   recommendMetadataNotCompleted,
	},
}

// protocolLayers is the layer each step's evidence must carry.
//
// It is checked as well as the step, so a node disagreeing with itself is a
// shape this rule declines to read rather than one it guesses at — the same
// check internal/diagnosis/transport applies to a handshake.
var protocolLayers = map[domain.Step]domain.Layer{
	servicekafka.StepAPIVersions:      domain.LayerProtocol,
	servicekafka.StepSASLHandshake:    domain.LayerAuth,
	servicekafka.StepSASLAuthenticate: domain.LayerAuth,
	servicekafka.StepMetadata:         domain.LayerTopology,
}

// Protocol reports what the Kafka protocol stages evidenced.
//
// It is a diagnosis.Rule. A caller wires it in beside the advertised-broker
// rules and the generic transport rules.
//
// # It needs no anchor, and that is not an oversight
//
// The transport rules descend from `target.requested` because a `tls.handshake`
// node is service-neutral: the same shape appears under a Kafka bootstrap target
// and under a broker the cluster advertised, and only provenance tells them
// apart. A `kafka.sasl_authenticate` node has no such ambiguity. The step name
// *is* the anchor — it is a Kafka fact produced by one adapter — which is the
// case docs/ARCHITECTURE.md section 5.5 describes. So this file walks no edges,
// reads no parent, needs no `Origin` and parses no identifier.
//
// # One node, at most one finding
//
// The table is keyed on the node's own step, state and failure class, so a node
// matches at most one entry. There is no precedence rule, no suppression pass
// and no second rule competing for these steps — the advertised-broker rules
// anchor at `kafka.broker_advertised` and require `kafka.metadata` to have
// passed, so they cannot fire on anything this owns.
//
// # What it does not own
//
// **Advertised-broker transport.** `AdvertisedEndpointUnreachable` and
// `UnusableAdvertisement` keep it, and ADR 0050 keeps those sweeps
// credential-free.
//
// **Success.** No `PASS` produces a finding; ADR 0052 makes the outcome line a
// renderer concern.
//
// **Local budget outcomes.** `UNKNOWN` with `EXEC_LOCAL_TIMEOUT` or
// `EXEC_CANCELLED` reaches the operator as `Result.Incomplete()`.
func Protocol(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	// Canonical node order in, deterministic findings out, before the engine
	// sorts anything.
	for _, node := range g.Nodes() {
		finding, ok := evaluateProtocol(g, node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateProtocol decides what one node supports.
func evaluateProtocol(g domain.Graph, node domain.Evidence) (domain.Finding, bool) {
	layer, owned := protocolLayers[node.Step()]
	if !owned || node.Layer() != layer {
		return domain.Finding{}, false
	}

	authorized, ok := protocolClaims[outcome{
		step:    node.Step(),
		state:   node.State(),
		failure: node.FailureClass(),
	}]
	if !ok {
		return domain.Finding{}, false
	}

	return buildProtocol(g, node, layer, authorized)
}

// buildProtocol assembles one finding.
func buildProtocol(
	g domain.Graph, node domain.Evidence, layer domain.Layer, c claim,
) (domain.Finding, bool) {
	finding, err := domain.NewFinding(domain.FindingInput{
		Code: c.code,
		// CONFIRMED throughout. Every claim restates a positively recorded
		// outcome with no inferential step: the endpoint said this, or svcdoctor
		// declined for a stated reason. Nothing is left open, so none carries a
		// discriminator and the model would reject one.
		Kind:       domain.FindingKindConfirmed,
		Severity:   c.severity,
		Confidence: domain.ConfidenceHigh,
		Layer:      layer,
		// The concrete peer the exchange ran against, taken from the node rather
		// than rebuilt. A protocol outcome is a fact about the endpoint that
		// produced it, so naming the logical bootstrap target would widen the
		// claim to addresses that were never asked.
		Subject:          node.Subject(),
		Summary:          c.summary,
		Detail:           detailWithMechanism(c.detail, node),
		EvidenceRefs:     protocolRefs(g, node, c.code),
		Recommendations:  recommend(c.recommendation),
		VantageDependent: c.vantageDependent,
	})
	if err != nil {
		// Unreachable. The subject comes from a node the graph validated, the
		// references come from that graph, and the prose is built from package
		// constants and a mechanism name the adapter recorded.
		// TestEveryAuthorizedOutcomeBuildsAValidFinding drives the whole table
		// and fails if this branch is ever taken.
		return domain.Finding{}, false
	}
	return finding, true
}

// protocolRefs names the evidence a claim rests on.
//
// The node itself, always, and nothing else — except for the policy refusal,
// which is the one claim whose subject is *why nothing was attempted*. That
// answer lives on another node, and the producer already recorded the edge to
// it. docs/FINDINGS.md section 3.1 item 11 forbids citing a blocked step as a
// cause; here the blocked step is the subject and its blocker is the cause,
// which is that rule read correctly. internal/diagnosis/postgres reads the same
// edge for the same finding.
//
// The requested-target anchor is deliberately never referenced: none of these
// claims is about the logical target, and no claim here makes a resolution claim.
func protocolRefs(g domain.Graph, node domain.Evidence, code domain.FindingCode) []domain.EvidenceID {
	refs := []domain.EvidenceID{node.ID()}
	if code != CodeCredentialWithheld {
		return refs
	}
	return append(refs, g.BlockedBy(node.ID())...)
}

// detailWithMechanism appends the mechanism a step concerned itself with.
//
// The mechanism is a protocol name from a public registry, already recorded on
// the node by the adapter and already shareable — it names neither a host nor a
// principal. It is appended rather than interpolated so that a node without the
// attribute yields the base prose instead of a sentence with a hole in it.
func detailWithMechanism(detail string, node domain.Evidence) string {
	value, ok := node.Attribute(servicekafka.AttrSASLMechanism)
	if !ok {
		return detail
	}
	mechanism, ok := value.Str()
	if !ok || mechanism == "" {
		return detail
	}
	return fmt.Sprintf("%s\nThe mechanism this step concerned was %s.", detail, mechanism)
}

// recommend wraps one action, dropping it if the model rejects the text.
func recommend(action string) []domain.Recommendation {
	recommendation, err := domain.NewRecommendation(action)
	if err != nil {
		// Unreachable: every action is a package constant, non-empty, trimmed
		// and free of control characters. Pinned by
		// TestProtocolRecommendationTextIsValid.
		return nil
	}
	return []domain.Recommendation{recommendation}
}
