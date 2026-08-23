package transport

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The five codes a failed requested-target TLS handshake can produce.
//
// # They carry no service prefix, and none mirrors a FailureClass
//
// The evidence is service-neutral, so the codes are too — as `DNS_*` and `TCP_*`
// in this package already are. That makes one hazard specific to them: a report
// carries `failureClass` on the evidence node and `code` on the finding, and
// PostgreSQL's `POSTGRES_` prefix keeps those two namespaces apart while a
// generic code cannot. So no code here repeats its class's spelling. Two names
// were rejected on exactly that ground during the ADR 0053 review:
// `TLS_PEER_NOT_TLS` mirrored `TLS_PEER_NOT_TLS` outright, and
// `TLS_HANDSHAKE_FAILED` sat one word from `TLS_HANDSHAKE_FAILURE`.
//
// They are five rather than one because the first move differs for each, which
// docs/FINDINGS.md section 3.1 item 11 makes the test for a merge.
const (
	// CodeTLSEndpointDoesNotSpeakTLS: the endpoint answered, and what it
	// answered with was not TLS.
	//
	// **Scoped to this endpoint and this attempt.** It does not say the endpoint
	// never supports TLS, that the service is not TLS-capable, that the port is
	// wrong, or that anything on the path interfered. Each of those is a cause,
	// and this is an observation.
	CodeTLSEndpointDoesNotSpeakTLS domain.FindingCode = "TLS_ENDPOINT_DOES_NOT_SPEAK_TLS"

	// CodeTLSIdentityMismatch: no name in the presented certificate matched the
	// identity this run asked to verify.
	CodeTLSIdentityMismatch domain.FindingCode = "TLS_IDENTITY_MISMATCH"

	// CodeTLSChainNotTrusted: the chain presented did not verify against this
	// run's trust context.
	//
	// The claim is about the *pairing* of a chain and a trust context, and the
	// trust context is frequently the half that is wrong.
	CodeTLSChainNotTrusted domain.FindingCode = "TLS_CHAIN_NOT_TRUSTED"

	// CodeTLSCertificateNotValidNow: the presented certificate's validity window
	// did not contain the time this run used.
	CodeTLSCertificateNotValidNow domain.FindingCode = "TLS_CERTIFICATE_NOT_VALID_NOW"

	// CodeTLSHandshakeNotCompleted is the floor: a handshake was attempted and
	// did not complete, and svcdoctor could not attribute why.
	CodeTLSHandshakeNotCompleted domain.FindingCode = "TLS_HANDSHAKE_NOT_COMPLETED"
)

// The prose. Each summary states the observation; each detail scopes it to this
// endpoint, this attempt and this vantage; each recommendation names somewhere
// to look without asserting what is wrong there.
const (
	summaryEndpointDoesNotSpeakTLS = "The endpoint answered, and what it sent was not TLS"
	detailEndpointDoesNotSpeakTLS  = "svcdoctor opened a connection to this endpoint and " +
		"began a TLS handshake, and the first thing the endpoint sent back was not a TLS " +
		"record.\n" +
		"That is what this run observed at this endpoint, on this attempt, from this vantage " +
		"point, and it is the whole of the claim. It does not establish that the endpoint " +
		"never speaks TLS, that the service behind it cannot, or what answered instead. " +
		"A listener that speaks another protocol, something terminating the connection in " +
		"between, and a port that serves plaintext all look identical from here."
	recommendEndpointDoesNotSpeakTLS = "Check what is listening on this endpoint and whether " +
		"this run was meant to negotiate TLS with it"

	summaryIdentityMismatch = "The certificate presented carries no name matching the " +
		"identity this run verified"
	detailIdentityMismatch = "The endpoint completed enough of the handshake to present a " +
		"certificate, and no name it carries matched the identity this run asked to verify.\n" +
		"The identity verified and the names presented are both recorded on the referenced " +
		"handshake evidence. Which certificate an endpoint presents can depend on the name " +
		"sent in SNI and on the path a connection took, so this is a statement about this " +
		"attempt rather than about the endpoint's configuration in general."
	recommendIdentityMismatch = "Compare the names on the presented certificate with the " +
		"identity this run verified, which is recorded on the referenced evidence"

	summaryChainNotTrusted = "The certificate chain presented did not verify against this " +
		"run's trust context"
	detailChainNotTrusted = "The endpoint presented a chain, and it did not verify against " +
		"the trust material this run was given.\n" +
		"This claim is about a pairing, and either half can be the reason. **The trust " +
		"context is this run's**: whether it was the system trust store or a file supplied " +
		"to this run is recorded on the referenced evidence, and a missing or wrong CA on " +
		"this side produces exactly this observation. The chain the endpoint served may " +
		"equally be incomplete or issued by an authority this run does not know. A chain " +
		"that fails here can verify from elsewhere, and one that verifies here can fail " +
		"elsewhere."
	recommendChainNotTrusted = "Check the trust material this run was given — the system " +
		"store or the supplied CA file — against the chain recorded on the referenced " +
		"evidence"

	summaryCertificateNotValidNow = "The certificate presented is outside its validity " +
		"window as measured by this run"
	detailCertificateNotValidNow = "The endpoint presented a certificate whose validity " +
		"window does not contain the time this run used.\n" +
		"Two values produce that comparison and this finding asserts nothing about which " +
		"is wrong: the window on the certificate, recorded on the referenced evidence as " +
		"its not-before and not-after, and the clock of the host svcdoctor ran on. A " +
		"certificate outside its window and a host whose clock is wrong are " +
		"indistinguishable from here."
	recommendCertificateNotValidNow = "Compare the certificate's validity window on the " +
		"referenced evidence with the clock of the host this run used"

	summaryHandshakeNotCompleted = "The TLS handshake with this endpoint did not complete"
	detailHandshakeNotCompleted  = "A TLS handshake was attempted with this endpoint and did " +
		"not complete.\n" +
		"That the handshake did not complete is certain; **why is not**. svcdoctor could " +
		"not attribute the failure to any of the outcomes it recognizes, so this finding " +
		"names none: it is not a statement about the certificate, the protocol version, " +
		"the cipher suites, a client certificate, or anything between this vantage point " +
		"and the endpoint. What the handshake observed is on the referenced evidence."
	recommendHandshakeNotCompleted = "Read the handshake outcome recorded on the referenced " +
		"evidence, and compare it with what this endpoint is configured to accept"
)

// tlsClaim is what one authorized FailureClass supports.
type tlsClaim struct {
	code           domain.FindingCode
	summary        string
	detail         string
	recommendation string
}

// tlsClaims maps a normalized TLS failure onto the claim it supports.
//
// **Closed on purpose.** A `FailureClass` absent from this table produces no
// finding, including one added to the domain later. A default branch folding
// anything unrecognized into the floor would silently grant a new producer a
// claim nobody reviewed — and the floor's own wording, "could not attribute",
// would become a statement about a class that may be perfectly attributable.
//
// Three declared TLS classes are deliberately absent because no producer emits
// them: `TLS_VERSION_MISMATCH`, `TLS_CLIENT_CERTIFICATE_REQUIRED` and
// `TLS_CLIENT_CERTIFICATE_REJECTED`. Verified against
// internal/probe/tls/handshake.go rather than assumed. Writing dead mappings
// would authorize claims for evidence that cannot occur, which is the failure
// ADR 0043 section 14 refused.
//
// The two certificate-validity classes share one code. They pose one question —
// *is this certificate valid now, and whose clock says so?* — and
// `tls.peer_not_before` and `tls.peer_not_after` preserve which end it was where
// a machine reads it.
var tlsClaims = map[domain.FailureClass]tlsClaim{
	domain.FailureTLSPeerNotTLS: {
		code:           CodeTLSEndpointDoesNotSpeakTLS,
		summary:        summaryEndpointDoesNotSpeakTLS,
		detail:         detailEndpointDoesNotSpeakTLS,
		recommendation: recommendEndpointDoesNotSpeakTLS,
	},
	domain.FailureTLSHostnameMismatch: {
		code:           CodeTLSIdentityMismatch,
		summary:        summaryIdentityMismatch,
		detail:         detailIdentityMismatch,
		recommendation: recommendIdentityMismatch,
	},
	domain.FailureTLSUnknownAuthority: {
		code:           CodeTLSChainNotTrusted,
		summary:        summaryChainNotTrusted,
		detail:         detailChainNotTrusted,
		recommendation: recommendChainNotTrusted,
	},
	domain.FailureTLSCertificateExpired: {
		code:           CodeTLSCertificateNotValidNow,
		summary:        summaryCertificateNotValidNow,
		detail:         detailCertificateNotValidNow,
		recommendation: recommendCertificateNotValidNow,
	},
	domain.FailureTLSCertificateNotYetValid: {
		code:           CodeTLSCertificateNotValidNow,
		summary:        summaryCertificateNotValidNow,
		detail:         detailCertificateNotValidNow,
		recommendation: recommendCertificateNotValidNow,
	},
	domain.FailureTLSHandshakeFailure: {
		code:           CodeTLSHandshakeNotCompleted,
		summary:        summaryHandshakeNotCompleted,
		detail:         detailHandshakeNotCompleted,
		recommendation: recommendHandshakeNotCompleted,
	},
}

// TLS reports failed TLS handshakes on the transport the requested target caused.
//
// It is a diagnosis.Rule. A caller wires it in with
// diagnosis.NewEngine(transport.DNS, transport.TCP, transport.TLS).
//
// # It descends from the anchor, like its siblings
//
// The rule enumerates requested-target sweeps and reads the handshakes that are
// **direct children** of a connection in one. It never asks a handshake what it
// hangs from: that question is provenance read off graph shape, and the walk
// here has its context by construction — it is looking at these nodes because it
// reached them from an anchor.
//
// The chain the sweep already validates is the ownership predicate:
//
//	target.requested -> dns.lookup -> tcp.connect -> tls.handshake
//	target.requested ->              tcp.connect -> tls.handshake
//
// with the anchor's layer and subject kind checked, at most one lookup, and
// handshakes taken as direct children only.
//
// The second shape is a target given as an address literal, which resolves
// nothing and therefore has no L1 node (ADR 0059). It reaches this rule through
// the same walk and needs nothing here: ownership is "a handshake directly under
// a connection under this anchor", and that sentence never mentioned DNS. The
// collection is what had to learn the second shape, and it did — which is how a
// literal TLS failure got an owner in the same change that made one reachable
// (ADR 0054).
//
// # It is endpoint-scoped, and DNS and TCP beside it are not
//
// The other two rules aggregate at the anchor and withhold on partial success,
// because their claims are about reachability: a client needs one working path,
// so *"no measured path reached the endpoint"* is a property of the address set
// that a single success falsifies.
//
// **A TLS claim is not about the set.** A certificate is presented by one
// endpoint, so *"10.0.4.17:9093 presented an expired certificate"* stays true
// whether or not a sibling address presented a valid one — and a client that
// selects the failing address gets the failure. Aggregating would force a choice
// wrong in both directions: asserting overclaims when a path works, withholding
// hides a defect a client may select tomorrow.
//
// So each failing endpoint produces its own finding and a passing sibling
// suppresses nothing. That is the conclusion ADR 0044 reached for PostgreSQL's
// in-band handshake, and keeping the two agree stops scope from becoming a
// property of whether a service negotiates TLS in band.
//
// # What it does not own
//
// **PostgreSQL in-band TLS.** Its handshake is a child of postgres.ssl_request,
// a grandchild of the connect, so collectSweep does not collect it and ADR 0044
// keeps it.
//
// **A Kafka advertised sweep.** Its lookup is a child of
// kafka.broker_advertised rather than of a requested-target anchor, so it forms
// no sweep here at all and ADR 0034 keeps it — even though it sits transitively
// below a bootstrap target and is otherwise the identical shape.
//
// Neither needs suppression, precedence, a service-name check, Origin or
// identifier parsing, and this file contains none.
func TLS(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	// Canonical sweep order, canonical handshake order, deterministic findings
	// before the engine sorts anything.
	for _, s := range collectSweeps(g) {
		if !s.wellFormed {
			continue
		}
		for _, pair := range s.handshakes {
			finding, ok := evaluateTLS(pair)
			if !ok {
				continue
			}
			out = append(out, finding)
		}
	}
	return out
}

// evaluateTLS decides what one handshake supports.
//
// Ownership is already established: the caller reached this node as a direct
// child of a connection in a requested-target sweep. What remains is the node's
// own shape and its failure class.
func evaluateTLS(pair upgrade) (domain.Finding, bool) {
	node := pair.handshake

	// The layer is checked as well as the step the sweep matched on. They agree
	// on every node the probe produces, and requiring both means a node
	// disagreeing with itself is a shape this rule declines to read rather than
	// one it guesses at.
	if node.Layer() != domain.LayerTLS {
		return domain.Finding{}, false
	}

	// **FAIL, not "not PASS".** This is the safety boundary of the rule.
	//
	// UNKNOWN with EXEC_LOCAL_TIMEOUT or EXEC_CANCELLED is svcdoctor's own budget
	// or a cancellation, and nothing was learned about the endpoint; turning
	// either into a TLS claim is the local-timeout-as-remote-failure mistake the
	// whole claim discipline exists to prevent. SKIPPED is a step a failed
	// prerequisite blocked, and docs/FINDINGS.md section 3.1 item 11 forbids
	// citing a blocked step as a cause. Those outcomes reach Result.Incomplete
	// through the application boundary, never a finding here.
	if node.State() != domain.StateFail {
		return domain.Finding{}, false
	}

	claim, authorized := tlsClaims[node.FailureClass()]
	if !authorized {
		return domain.Finding{}, false
	}

	// The subject is the handshake's own — the concrete endpoint that presented
	// what was observed. Not the anchor's logical target: that would misdescribe
	// which endpoint this is about.
	return build(buildInput{
		code:    claim.code,
		layer:   domain.LayerTLS,
		subject: node.Subject(),
		// The handshake carries the observation and the certificate facts; the
		// connection establishes that a socket existed to hand to it. The lookup
		// and the anchor are not referenced: this finding makes no resolution
		// claim and no claim about the logical target.
		refs:           []domain.EvidenceID{node.ID(), pair.connect.ID()},
		summary:        claim.summary,
		detail:         claim.detail,
		recommendation: claim.recommendation,
	})
}
