package postgres

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The five codes for a handshake PostgreSQL asked for and did not get.
//
// # Why this package owns a generic probe's node at all
//
// The handshake is performed by internal/probe/tls and its node carries a
// generic step name, so at first sight it is transport evidence. It is not. The
// handshake exists *only because* this service negotiated an upgrade in band,
// and the adapter records that by parenting the node to `postgres.ssl_request`
// rather than to `tcp.connect` — deliberately, so that "PostgreSQL asked for
// this" is not lost.
//
// ADR 0044 turns that into the ownership rule, and the general form is one
// sentence: **a generic probe's evidence belongs to the layer that caused the
// probe to run, read from the parent edge that layer already recorded.** Redis
// and MySQL inherit it unchanged if they ever negotiate in band.
//
// This is not the provenance inference ADR 0034 section 4 forbids. That
// prohibition is about reading how a *subject* entered a run off the shape
// around a node. Here the producer wrote the edge to say why the execution
// happened, and reading it is reading what the graph states about an execution —
// the same distinction that lets a Kafka rule walk down from an advertisement.
const (
	// CodeTLSUpgradeNotHonored reports an endpoint that agreed to encrypt and
	// then did not speak TLS.
	//
	// The name says what the endpoint did, not what it is. "Not PostgreSQL" is
	// the tempting reading and is unsupported: the same observation is produced
	// by a pooler in front of a backend, by a plaintext listener behind a
	// rewrite, and by anything else that answers a byte and then does not
	// continue. svcdoctor observed an agreement and an absence of TLS, and that
	// is the whole claim.
	CodeTLSUpgradeNotHonored domain.FindingCode = "POSTGRES_TLS_UPGRADE_NOT_HONORED"

	// CodeTLSIdentityMismatch reports a certificate carrying no name this run
	// asked for.
	//
	// "Identity" rather than "hostname" because certificate identity includes
	// addresses, and the run may legitimately verify either.
	CodeTLSIdentityMismatch domain.FindingCode = "POSTGRES_TLS_IDENTITY_MISMATCH"

	// CodeTLSChainNotTrusted reports a chain that did not verify against the
	// trust context this run was given.
	//
	// It is the one code here that frequently names a defect on **svcdoctor's**
	// side rather than the endpoint's, which is why the claim is about the
	// configured trust context rather than about the certificate's validity in
	// general.
	CodeTLSChainNotTrusted domain.FindingCode = "POSTGRES_TLS_CHAIN_NOT_TRUSTED"

	// CodeTLSCertificateNotValidNow reports a certificate outside its validity
	// window.
	//
	// One code for both ends of the window. Expired and not-yet-valid pose the
	// same question — *is this certificate valid now, and whose clock says so?*
	// — and `tls.peer_not_before` and `tls.peer_not_after` on the cited node
	// answer which end exactly. Splitting them would duplicate in a code what
	// the evidence already carries structurally.
	CodeTLSCertificateNotValidNow domain.FindingCode = "POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW"

	// CodeTLSHandshakeFailed is the floor.
	//
	// It is not a rare case: a *received* protocol_version alert arrives as an
	// unexported error type, and the TLS probe refuses to match error text, so
	// a version mismatch lands here rather than in a version-specific class.
	CodeTLSHandshakeFailed domain.FindingCode = "POSTGRES_TLS_HANDSHAKE_FAILED"
)

// The prose. Every summary names the in-band context, because the same failure
// class under a generic transport chain would be a different finding with a
// different owner.
const (
	summaryTLSUpgradeNotHonored = "The PostgreSQL endpoint agreed to encrypt this connection " +
		"and then did not complete a TLS handshake"

	detailTLSUpgradeNotHonored = "svcdoctor sent an SSLRequest, the endpoint answered that it " +
		"would encrypt, and what answered next was not a TLS record.\n" +
		"This does not establish what answered. A connection pooler, a plaintext listener and " +
		"anything else that accepts the connection produce the same observation, and svcdoctor " +
		"observed none of them.\n" +
		"What responds on a given path can differ by network position."

	summaryTLSIdentityMismatch = "The certificate presented for the PostgreSQL TLS upgrade " +
		"does not match the identity this run verified"

	detailTLSIdentityMismatch = "The endpoint agreed to encrypt and presented a certificate, " +
		"and no name it carries matched the server identity this run asked for. The requested " +
		"identity and the names the certificate carries are both recorded on the referenced " +
		"evidence.\n" +
		"This says nothing about whether the certificate is otherwise valid, nor about who " +
		"issued it.\n" +
		"What is presented on a given path can differ by network position."

	summaryTLSChainNotTrusted = "The certificate chain presented for the PostgreSQL TLS " +
		"upgrade did not verify against this run's trust context"

	detailTLSChainNotTrusted = "The endpoint agreed to encrypt and presented a chain that did " +
		"not verify against the trust material this run was given. Whether that material was " +
		"the system store or supplied to this run is recorded on the referenced evidence.\n" +
		"A chain that does not verify here may verify elsewhere: this is a statement about " +
		"this run's trust context as much as about the chain."

	summaryTLSCertificateNotValidNow = "The certificate presented for the PostgreSQL TLS " +
		"upgrade is outside its validity window"

	detailTLSCertificateNotValidNow = "The endpoint agreed to encrypt and presented a " +
		"certificate whose validity window does not contain the moment this run measured it. " +
		"The window is recorded on the referenced evidence, alongside the time the handshake " +
		"started.\n" +
		"The comparison was made against this host's clock, so a clock that is wrong here " +
		"produces this outcome against a certificate that is valid.\n" +
		"What is presented on a given path can differ by network position."

	summaryTLSHandshakeFailed = "The PostgreSQL TLS handshake did not complete after the " +
		"endpoint agreed to encrypt"

	detailTLSHandshakeFailed = "The endpoint answered that it would encrypt this connection " +
		"and the handshake that followed did not complete.\n" +
		"svcdoctor could not attribute this outcome to a specific cause. Several unrelated " +
		"conditions reach it, including a protocol version neither side would accept, which " +
		"arrives in a form this tool declines to identify by its text."
)

// The recommendations. Each names something to inspect and asserts no cause.
const (
	recommendTLSUpgradeNotHonored = "Check what terminates connections at this endpoint after " +
		"PostgreSQL SSL negotiation, and whether it is the component expected to serve TLS"

	recommendTLSIdentityMismatch = "Compare the certificate names recorded on the referenced " +
		"evidence with the server identity this run was asked to verify"

	recommendTLSChainNotTrusted = "Check the trust material this run was given against the " +
		"chain recorded on the referenced evidence"

	recommendTLSCertificateNotValidNow = "Compare the certificate validity window recorded on " +
		"the referenced evidence with this host's clock"

	recommendTLSHandshakeFailed = "Read the referenced evidence for what the handshake " +
		"recorded, and check whether the protocol versions this run offered are acceptable " +
		"to this endpoint"
)

// tlsClaim is one authorized mapping from a measured class to a stated claim.
type tlsClaim struct {
	code           domain.FindingCode
	summary        string
	detail         string
	recommendation string
}

// tlsClaims is the closed mapping ADR 0044 section 5 fixes.
//
// **Closed on purpose.** A `FailureClass` absent from this table produces no
// finding, including one added to the domain later. The alternative — a default
// branch folding anything unrecognized into the floor — would silently give a
// new producer a claim nobody reviewed, and the floor's own wording ("could not
// attribute") would become a statement about a class that may well be perfectly
// attributable.
//
// Three declared TLS classes are deliberately absent because no producer emits
// them: TLS_VERSION_MISMATCH, TLS_CLIENT_CERTIFICATE_REQUIRED and
// TLS_CLIENT_CERTIFICATE_REJECTED. Writing dead mappings for them would be
// authorizing claims for evidence that cannot occur.
var tlsClaims = map[domain.FailureClass]tlsClaim{
	domain.FailureTLSPeerNotTLS: {
		code:           CodeTLSUpgradeNotHonored,
		summary:        summaryTLSUpgradeNotHonored,
		detail:         detailTLSUpgradeNotHonored,
		recommendation: recommendTLSUpgradeNotHonored,
	},
	domain.FailureTLSHostnameMismatch: {
		code:           CodeTLSIdentityMismatch,
		summary:        summaryTLSIdentityMismatch,
		detail:         detailTLSIdentityMismatch,
		recommendation: recommendTLSIdentityMismatch,
	},
	domain.FailureTLSUnknownAuthority: {
		code:           CodeTLSChainNotTrusted,
		summary:        summaryTLSChainNotTrusted,
		detail:         detailTLSChainNotTrusted,
		recommendation: recommendTLSChainNotTrusted,
	},
	domain.FailureTLSCertificateExpired: {
		code:           CodeTLSCertificateNotValidNow,
		summary:        summaryTLSCertificateNotValidNow,
		detail:         detailTLSCertificateNotValidNow,
		recommendation: recommendTLSCertificateNotValidNow,
	},
	domain.FailureTLSCertificateNotYetValid: {
		code:           CodeTLSCertificateNotValidNow,
		summary:        summaryTLSCertificateNotValidNow,
		detail:         detailTLSCertificateNotValidNow,
		recommendation: recommendTLSCertificateNotValidNow,
	},
	domain.FailureTLSHandshakeFailure: {
		code:           CodeTLSHandshakeFailed,
		summary:        summaryTLSHandshakeFailed,
		detail:         detailTLSHandshakeFailed,
		recommendation: recommendTLSHandshakeFailed,
	},
}

// TLS reports handshakes that failed after a PostgreSQL endpoint agreed to
// encrypt the connection.
//
// It is a diagnosis.Rule, wired beside the four that anchor at `postgres.*`
// steps and independent of all of them.
//
// # It is endpoint-scoped, and that is the difference from generic transport
//
// ADR 0043's `TCP_CONNECTION_NOT_ESTABLISHED` claims something about *the
// requested target*, so one working path makes it false and withholds it. Every
// finding here claims something about **this endpoint**: it presented this
// certificate, it did not complete this handshake. A second address working does
// not make that false, so a passing handshake elsewhere withholds nothing.
//
// A dual-stack endpoint whose IPv4 address presents a bad certificate while IPv6
// works is a real defect that a client meets whenever it selects IPv4, and
// suppressing it would hide the fact an operator needs. The report says both
// things: this finding, and — through ADR 0041's selection — a session that
// succeeded elsewhere.
//
// For the same reason a mixed FAIL and UNKNOWN sweep needs no rule. Each node is
// judged alone; the failed one yields its finding and the unmeasured one yields
// nothing. `Result.Incomplete()` and exit code 4 continue to report that the run
// did not finish, and docs/SCOPE.md already ranks code 4 above code 1 so
// incompleteness qualifies the conclusion.
//
// # What it never reads
//
// Nothing above the negotiation and nothing below it. Not the transport nodes,
// not the anchor, and not `postgres.startup`, `postgres.authentication` or
// `postgres.session`. It changes no path selection, presents no credential and
// introduces no retry.
func TLS(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	// Canonical node order in, deterministic order out, before the engine sorts.
	for _, node := range g.Nodes() {
		if node.Step() != vocabulary.StepTLSHandshake {
			continue
		}
		finding, ok := evaluateTLS(g, node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateTLS applies ADR 0044 section 3 to one handshake node.
func evaluateTLS(g domain.Graph, node domain.Evidence) (domain.Finding, bool) {
	// The layer is checked as well as the step. The two agree on every node the
	// probe produces, and requiring both means a node that disagreed with itself
	// is a shape this rule declines to read rather than one it guesses at.
	if node.Layer() != domain.LayerTLS {
		return domain.Finding{}, false
	}

	// FAIL, not "not PASS". The adapter mints a SKIPPED handshake node with a
	// blockedBy edge when the negotiation did not deliver a socket, and
	// docs/FINDINGS.md section 3.1 item 11 forbids citing a blocked step as a
	// cause. It also excludes the UNKNOWN states cancellation and an exhausted
	// budget produce: svcdoctor's own limits are never a claim about a peer.
	if node.State() != domain.StateFail {
		return domain.Finding{}, false
	}

	negotiation, ok := soleParent(g, node)
	if !ok {
		return domain.Finding{}, false
	}

	// This is the ownership test. A handshake performed by the generic transport
	// chain hangs off a tcp.connect node — for a requested target and for a
	// Kafka advertised sweep alike — so neither can reach this branch.
	if negotiation.Step() != servicepostgres.StepSSLRequest {
		return domain.Finding{}, false
	}

	// The negotiation must have succeeded, and this carries two things. It makes
	// the claim "the endpoint agreed to encrypt and then..." true rather than
	// assumed, and it keeps this rule disjoint from SSLRequest: a declined or
	// errored negotiation is a FAIL node that rule owns, and the handshake
	// beneath it is SKIPPED rather than FAIL in any case.
	if negotiation.State() != domain.StatePass {
		return domain.Finding{}, false
	}

	// Both nodes describe the same concrete endpoint. Free to check, and it
	// closes the malformed case where a handshake is attached to a negotiation
	// of a different address — where "this endpoint agreed and then failed"
	// would be two statements about two endpoints.
	if node.Subject() != negotiation.Subject() {
		return domain.Finding{}, false
	}

	claim, ok := tlsClaims[node.FailureClass()]
	if !ok {
		return domain.Finding{}, false
	}

	return build(domain.FindingInput{
		Code: claim.code,
		// Each claim restates a positively evidenced failure with an exact
		// class, and nothing is left open. FindingKindConfirmed does not require
		// a proven root cause, which is why the floor qualifies too — its claim
		// includes that the cause was not attributed.
		Kind: domain.FindingKindConfirmed,
		// The run required an encrypted channel, this endpoint did not deliver
		// one, and nothing further could be attempted on this connection. That
		// is what prevents correct use of this endpoint, and it matches
		// CodeTLSDeclined, the adjacent claim.
		Severity: domain.SeverityError,
		// The claim is the measurement. No inferential step separates "the chain
		// did not verify" from what the handshake recorded.
		Confidence: domain.ConfidenceHigh,
		// The claim's layer is the handshake's own.
		Layer:   domain.LayerTLS,
		Subject: node.Subject(),
		Summary: claim.summary,
		Detail:  claim.detail,
		// True for every code here, and asserted rather than defaulted. ADR 0040
		// section 6.1 fixes two grounds: the observation is path-dependent, or
		// the cause is unattributed and a source-keyed one cannot be excluded.
		// The four classified codes rest on the first — every one of them is
		// about material a peer *presented*, and what is presented is exactly
		// what an element on the path can change, which is the reasoning
		// CodePeerVerificationFailed already carries. The floor rests on the
		// second, like the three PostgreSQL floors.
		//
		// The `false` set in this package is the findings where the peer reached
		// a catalog or credential decision. Nothing here is in that class.
		VantageDependent: true,
		// The handshake carries the failure, its class and every certificate
		// attribute; the negotiation carries the other half of the claim — that
		// this endpoint agreed to encrypt — without which the summaries have no
		// antecedent. Nothing above is cited: neither the connection nor the
		// anchor proves anything about TLS.
		EvidenceRefs:    []domain.EvidenceID{negotiation.ID(), node.ID()},
		Recommendations: recommend(claim.recommendation),
	})
}

// soleParent returns a node's parent when it has exactly one.
//
// Stricter than parentWithStep, and deliberately so. That helper accepts a node
// with several parents as long as one matches the step it was asked for, which
// is right for a rule reaching for a known relative. This rule is deciding
// *ownership*, and a handshake with two parents is a shape no producer makes: it
// would mean two layers each recorded having caused the same execution, and
// picking one would be choosing an owner by traversal order.
func soleParent(g domain.Graph, node domain.Evidence) (domain.Evidence, bool) {
	parents := g.Parents(node.ID())
	if len(parents) != 1 {
		return domain.Evidence{}, false
	}
	parent, ok := g.Node(parents[0])
	return parent, ok
}
