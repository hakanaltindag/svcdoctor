package postgres

import (
	"crypto/x509"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// ErrInvalidInput reports that the adapter was called with something it cannot
// use.
//
// It is the only error class this package returns. A server that declines TLS, a
// startup the server rejects, a peer that turns out not to speak PostgreSQL —
// those are diagnostic facts and come back as evidence.
var ErrInvalidInput = errors.New("invalid postgres adapter input")

// TLSPlan says what the caller wants done about transport encryption.
//
// Two values, and deliberately not libpq's six. `verify-ca` and `verify-full`
// are not modes here because certificate verification and trust source are
// already parameters of the TLS probe, and `prefer` is refused outright: falling
// back from a failed TLS handshake to a working plaintext one would swallow the
// expired certificate, untrusted CA or hostname mismatch that a diagnostic run
// exists to find. See ADR 0036 section 4.
//
// The zero value is TLSRequired, so a plan that was never set, never parsed or
// never threaded through a call chain asks for encryption rather than dropping
// it. That is the same failure direction security.CredentialTransportPolicy
// chooses.
type TLSPlan int

const (
	// TLSRequired sends an SSLRequest and continues only if the server accepts.
	//
	// A server answering 'N' ends the run at L3 with a recorded failure. There
	// is no fallback.
	TLSRequired TLSPlan = iota

	// TLSDisabled speaks to the endpoint in the clear, and does not ask.
	//
	// **No SSLRequest is sent**, which is a correction to ADR 0036 section 4
	// forced by measurement rather than a shortcut. That section said the
	// request would still be sent under this plan and the session would
	// "continue in plaintext regardless"; a real PostgreSQL 18.6 server proves
	// it cannot. A server that answers 'S' has already handed the socket to its
	// TLS layer and is waiting for a ClientHello, so a plaintext StartupMessage
	// after 'S' is read as a TLS record, rejected, and the connection closed —
	// observed as EOF, with `could not accept SSL connection: wrong version
	// number` in the server's log. libpq does not ask under `disable` either.
	//
	// The fact the ADR wanted is preserved. `postgres.ssl_request` is still
	// recorded, as SKIPPED with EXEC_SKIPPED_BY_POLICY, which states positively
	// that no TLS was attempted on this connection and why. That node is what a
	// plaintext channel points at, so ADR 0030's missing blocker carrier is
	// supplied exactly as ADR 0036 section 2 intended.
	TLSDisabled
)

// String returns a stable name for evidence and tests.
func (p TLSPlan) String() string {
	if p == TLSDisabled {
		return "disabled"
	}
	return "required"
}

// TLSOptions carries what the handshake needs beyond the connection.
//
// It is a small local struct rather than a reuse of transport.TLSOptions,
// because the two are requests to different layers: that one asks the transport
// chain to handshake immediately after TCP, and this one describes a handshake
// PostgreSQL triggers itself. Sharing the type would tie this package to
// transport orchestration for a struct with no behaviour.
//
// The zero value verifies against the system trust store.
type TLSOptions struct {
	// ServerName is the identity to verify and to send in SNI. When empty the
	// host part of Params.Endpoint is used, which is the name a client would
	// send. It is never derived from the resolved address.
	ServerName string

	// RootCAs is the trust source. Nil means the system trust store. This
	// package loads nothing from disk.
	RootCAs *x509.CertPool

	// MinVersion and MaxVersion bound the protocol versions offered. Zero means
	// the standard library's default.
	MinVersion uint16
	MaxVersion uint16

	// InsecureSkipVerify disables identity verification for this attempt. It is
	// explicit, never an automatic fallback, and the resulting channel is
	// tls-unverified, which the default credential policy refuses.
	InsecureSkipVerify bool
}

// Params describes one PostgreSQL negotiation over one measured connection.
type Params struct {
	// TLS is the transport-encryption plan. The zero value requires TLS.
	TLS TLSPlan

	// TLSOptions configures the handshake TLSRequired performs. Ignored under
	// TLSDisabled.
	TLSOptions TLSOptions

	// StepTimeout optionally bounds each exchange, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	StepTimeout time.Duration
}

// validate rejects input that cannot produce a meaningful negotiation.
func (p Params) validate() error {
	if p.StepTimeout < 0 {
		return ErrInvalidInput
	}
	return nil
}

// StartupParams is the identity the StartupMessage declares.
//
// **There is no password field and no security.Secret field.** Phase 4.3
// authenticates nothing, and a credential therefore has no path into this
// struct: "no credential is sent" is a property of the type rather than a
// promise about the code.
//
// User and Database are identity, not secrets. They are targeting parameters of
// the same kind as a hostname — svcdoctor already puts a hostname in a DNS query
// and an SNI extension in the clear — and gating them on the credential
// transport policy would make plaintext PostgreSQL undiagnosable. What protects
// them is redaction: both are recorded through domain.IdentityAttr and become
// identity-NNN in a shareable report (ADR 0037).
type StartupParams struct {
	// User is the role to connect as. Required: the protocol has no anonymous
	// startup, which is why this phase cannot reach an authentication request
	// without disclosing it.
	User string

	// Database is the database to select. Optional; a server given none
	// defaults to one named after the user.
	Database string

	// ExchangeTimeout optionally bounds the exchange, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	//
	// The name matches AuthParams, the other step that bounds exactly one
	// exchange; Params.StepTimeout is spelled differently because it bounds two
	// — the negotiation and the handshake that may follow it.
	//
	// **It was absent until Phase 4.11d, and the absence was a defect.** A
	// caller whose own context carried no deadline had nothing bounding this
	// step at all, so a peer that accepted the connection and never answered the
	// StartupMessage held the run open indefinitely — measured, against a
	// loopback listener, with a step timeout configured and ignored. Every
	// sibling step in this package took its budget from the same
	// PostgresParams.StepTimeout; this one silently dropped it, because there
	// was no field for it to arrive in.
	ExchangeTimeout time.Duration
}

func (p StartupParams) validate() error {
	if p.User == "" {
		return ErrInvalidInput
	}
	if !printable(p.User) || !printable(p.Database) {
		return ErrInvalidInput
	}
	if p.ExchangeTimeout < 0 {
		return ErrInvalidInput
	}
	return nil
}

// printable rejects control characters, which cannot appear in an evidence
// identifier or attribute and would terminate a protocol string early.
func printable(s string) bool {
	if strings.ContainsRune(s, 0) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// target is the pair of values every node in one negotiation shares.
//
// It is separate from Params because it is not a caller's request: it is what
// the measured connection already is. It comes from the transport continuation
// rather than being passed again, so the protocol nodes and the transport nodes
// cannot come to describe different things.
type target struct {
	endpoint string
	address  netip.AddrPort
	scope    probe.SweepScope
	parent   domain.EvidenceID
}
