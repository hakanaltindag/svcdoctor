package tls

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// StepHandshake names the operation this probe performs.
//
// It is exported because it is part of the report contract: the same string
// appears in every report and will be matched by automation, so a second copy of
// it as a literal elsewhere is a bug waiting to happen.
//
// **The canonical spelling moved to internal/vocabulary and this is an alias for
// it**, on the same terms as dns.StepLookup. See ADR 0042 section 11.
//
// A node carrying this step is not automatically generic transport evidence:
// internal/adapter/postgres records one for its in-band upgrade too. Ownership
// comes from the parent edge, not from the name.
const StepHandshake = vocabulary.StepTLSHandshake

// The attributes this probe records. Each is a fact the handshake directly
// observed and that nothing else in the evidence already carries; see the
// attribute section of ADR 0020 for why the list is not longer.
const (
	// AttrServerName is the identity the peer's certificate was checked against.
	// It is not the subject: the subject is the address the socket reached.
	AttrServerName domain.AttributeKey = "tls.server_name"

	// AttrVerified reports whether this handshake verified the peer's identity.
	// It is false when verification was disabled and false when the handshake
	// failed. It is always recorded, because "identity was not verified" is a
	// statement rather than an absence.
	AttrVerified domain.AttributeKey = "tls.verified"

	// AttrTrustSource says where the roots came from: system or custom. It is
	// absent when verification was disabled, because no trust source was used.
	AttrTrustSource domain.AttributeKey = "tls.trust_source"

	// AttrVersion is the negotiated protocol version, such as "TLS1.3".
	AttrVersion domain.AttributeKey = "tls.version"

	// AttrCipherSuite is the negotiated cipher suite's standard name.
	AttrCipherSuite domain.AttributeKey = "tls.cipher_suite"

	// AttrPeerCertificateCount is how many certificates the peer presented. A
	// chain of one is how "the server forgot its intermediates" looks.
	AttrPeerCertificateCount domain.AttributeKey = "tls.peer_certificate_count"

	// AttrPeerNotBefore and AttrPeerNotAfter are the leaf's validity window.
	// Whether an expiry is close enough to matter is diagnosis policy.
	AttrPeerNotBefore domain.AttributeKey = "tls.peer_not_before"
	AttrPeerNotAfter  domain.AttributeKey = "tls.peer_not_after"

	// AttrPeerDNSNames and AttrPeerIPAddresses are the leaf's subject
	// alternative names, one identity per list entry so that structural
	// redaction can recognize each of them.
	AttrPeerDNSNames    domain.AttributeKey = "tls.peer_dns_names"
	AttrPeerIPAddresses domain.AttributeKey = "tls.peer_ip_addresses"
)

// ErrInvalidInput reports that the probe was called with something it cannot
// use, such as a nil connection or an empty server name.
//
// It is the only error class this package returns. A rejected certificate is a
// diagnostic fact and comes back as evidence; a missing server name is a defect
// in the caller and comes back as an error.
var ErrInvalidInput = errors.New("invalid tls probe input")

// Handshake performs a TLS handshake over conn and returns what happened.
//
// # It takes ownership of conn, always
//
// After this call the connection is never the caller's again, in every outcome
// including a returned error. On failure it is closed here; on success the
// returned Result owns the TLS connection wrapping it. A caller that also closed
// it would be closing a connection somebody else owns, and a caller that had to
// remember which outcome left it responsible would eventually forget.
//
// # It never opens a connection
//
// There is no dialing and no name resolution here. The handshake happens over
// the socket it was handed, which is the whole point: the protocol layer must
// speak over the connection whose establishment was measured (ADR 0021).
//
// An error is returned only for unusable input or for a failure to construct
// valid evidence. Every handshake outcome, including every rejection, is
// reported through the evidence.
func Handshake(ctx context.Context, conn net.Conn, params Params) (*Result, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: connection must not be nil", ErrInvalidInput)
	}
	if ctx == nil {
		// The connection is already ours, so it is closed rather than leaked.
		_ = conn.Close()
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return newResult(observe(ctx, conn, params))
}

// observation is the producer-local record of one handshake.
//
// It holds the raw handshake error, the connection state and the live TLS
// connection, which is exactly what must not reach the canonical model. Keeping
// it unexported is what guarantees they cannot: normalization happens inside
// this package, and what leaves it is evidence plus an explicitly owned
// resource.
type observation struct {
	params Params
	conn   *cryptotls.Conn
	state  cryptotls.ConnectionState

	// err is what the handshake returned, and ctxErr is what the caller's
	// context reported at the same moment. Both are needed for the same reason
	// as in the DNS and TCP probes: the standard library's error does not always
	// say whose deadline expired.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observe performs the handshake and records what happened.
//
// This is the only function in the package that performs I/O or reads a clock.
// Everything after it is a pure transformation of the observation.
//
// cryptotls.Client never fails and never writes to the connection, so from this
// point the wrapper owns the socket: closing it closes the connection
// underneath, and there is no moment where two values could both be closed.
func observe(ctx context.Context, conn net.Conn, params Params) observation {
	wrapped := cryptotls.Client(conn, params.config())

	startedAt := time.Now()
	err := wrapped.HandshakeContext(ctx)
	duration := time.Since(startedAt)

	o := observation{
		params:    params,
		conn:      wrapped,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
	if err == nil {
		o.state = wrapped.ConnectionState()
	}
	return o
}

// newResult normalizes the observation and settles ownership.
//
// A failed handshake closes the connection: there is nothing to hand on, and
// leaving it open would leak a socket for every unreachable endpoint in a
// topology sweep. A failure to build evidence closes it too — that path should
// be unreachable, but a probe that returned an error while holding an open
// socket would leak one, and the guard costs a line.
func newResult(o observation) (*Result, error) {
	evidence, err := o.evidence()
	if err != nil {
		_ = o.conn.Close()
		return nil, err
	}
	if o.err != nil {
		_ = o.conn.Close()
		return &Result{evidence: evidence}, nil
	}
	// verified comes from the same observation that produced the evidence's
	// tls.verified attribute, so the two cannot disagree about one handshake.
	return &Result{evidence: evidence, verified: o.verified(), conn: o.conn}, nil
}

// evidence normalizes the observation into the canonical model.
//
// This is the probe boundary. Above it there are certificates, a connection
// state and a handshake error; below it there is a layer, a step, a state, a
// failure class and normalized values.
func (o observation) evidence() (domain.Evidence, error) {
	address := o.params.address()

	subject, err := domain.NewEndpointSubject(address.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		// The same components as the TCP node, distinguished by the step, so one
		// endpoint's L2 and L3 facts sit together and never collide (ADR 0019).
		ID: probe.ScopedEvidenceID(
			o.params.Scope, StepHandshake, o.params.Endpoint, address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerTLS,
		Step:         StepHandshake,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the contract, and it is the same one the DNS and
// TCP probes use:
//
//  1. A handshake that completed is a completed measurement. A context that
//     expires immediately afterwards does not unmake it, and the connection it
//     produced is still usable.
//  2. Otherwise the caller's context is consulted first, because svcdoctor's own
//     deadline expiring means nothing was learned about the peer.
//  3. Then the typed error, which is the standard library's own account.
//  4. Then any remaining timeout, attributed to svcdoctor rather than the peer.
func (o observation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	if class, ok := classifyHandshakeError(o.err, o.startedAt); ok {
		return domain.StateFail, class
	}
	if isTimeout(o.err) {
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	return domain.StateFail, domain.FailureTLSHandshakeFailure
}

// classifyHandshakeError maps a typed handshake error onto the domain
// vocabulary, and reports whether it recognized one.
//
// Only typed errors are inspected. Error text is never matched: it differs by
// platform and Go release, so a probe that matched it would make confident
// claims that quietly stop being true.
//
// # Two distinctions the standard library does not expose
//
// A *received* protocol_version alert arrives as an unexported error type, so a
// version mismatch is recorded as a generic handshake failure rather than as
// TLS_VERSION_MISMATCH. Inventing the precise class from the error's text is
// exactly the temptation this package refuses.
//
// Certificate chain verification is performed by the platform verifier on some
// systems, which returns an opaque error rather than x509.UnknownAuthorityError.
// So the fallback for any unrecognized verification failure is
// TLS_UNKNOWN_AUTHORITY, whose contract is "the chain did not verify against the
// trust source" — which is precisely what a CertificateVerificationError proves,
// on every platform, whatever its inner error turns out to be.
func classifyHandshakeError(err error, startedAt time.Time) (domain.FailureClass, bool) {
	var recordErr cryptotls.RecordHeaderError
	if errors.As(err, &recordErr) {
		// The peer answered with something that is not a TLS record. The
		// endpoint does not speak TLS, which is a different fact from TLS
		// failing.
		return domain.FailureTLSPeerNotTLS, true
	}

	var verificationErr *cryptotls.CertificateVerificationError
	if !errors.As(err, &verificationErr) {
		return domain.FailureNone, false
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return domain.FailureTLSHostnameMismatch, true
	}

	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) && invalidErr.Reason == x509.Expired {
		// x509 reports "outside the validity window" as one reason for both
		// ends of it. The certificate's own dates say which end, which is a
		// structured comparison rather than a reading of the error's prose.
		if invalidErr.Cert != nil && startedAt.Before(invalidErr.Cert.NotBefore) {
			return domain.FailureTLSCertificateNotYetValid, true
		}
		return domain.FailureTLSCertificateExpired, true
	}

	return domain.FailureTLSUnknownAuthority, true
}

// isTimeout reports whether err describes a deadline rather than a peer
// behaviour, after typed handshake errors have been ruled out.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// attributes records the facts the handshake yielded.
//
// An attribute appears when the observation actually produced it. A failed
// handshake has no negotiated version, and a handshake that never reached the
// peer's certificates has no certificate facts, so those keys are absent rather
// than empty: an absent fact and a zero value are different things.
func (o observation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrServerName: domain.HostAttr(o.params.ServerName),
		AttrVerified:   domain.BoolAttr(o.verified()),
	}
	if source := o.params.trustSource(); source != "" {
		attributes[AttrTrustSource] = domain.StringAttr(source)
	}

	if o.err == nil {
		attributes[AttrVersion] = domain.StringAttr(versionName(o.state.Version))
		attributes[AttrCipherSuite] = domain.StringAttr(cryptotls.CipherSuiteName(o.state.CipherSuite))
	}

	certificates := o.peerCertificates()
	if len(certificates) == 0 {
		return attributes
	}
	attributes[AttrPeerCertificateCount] = domain.IntAttr(int64(len(certificates)))

	leaf := certificates[0]
	attributes[AttrPeerNotBefore] = domain.TimeAttr(leaf.NotBefore)
	attributes[AttrPeerNotAfter] = domain.TimeAttr(leaf.NotAfter)

	if names := canonicalDNSNames(leaf.DNSNames); len(names) > 0 {
		attributes[AttrPeerDNSNames] = domain.HostListAttr(names...)
	}
	if addresses := canonicalIPs(leaf.IPAddresses); len(addresses) > 0 {
		attributes[AttrPeerIPAddresses] = domain.HostListAttr(addresses...)
	}
	return attributes
}

// verified reports whether this handshake established the peer's identity.
//
// It requires both a completed handshake and verification having been enabled.
// A handshake with verification disabled proves the channel is encrypted and
// nothing about who is on the other end, and the two must never read the same.
func (o observation) verified() bool {
	return o.err == nil && !o.params.InsecureSkipVerify
}

// peerCertificates returns the certificates the peer presented, from whichever
// source the outcome makes available.
//
// A successful handshake exposes them through the connection state. A
// verification failure exposes the same chain through the error, which is why a
// rejected certificate can still report which names it carried — usually the
// most useful thing in the report when a handshake fails.
func (o observation) peerCertificates() []*x509.Certificate {
	if o.err == nil {
		return o.state.PeerCertificates
	}
	var verificationErr *cryptotls.CertificateVerificationError
	if errors.As(o.err, &verificationErr) {
		return verificationErr.UnverifiedCertificates
	}
	return nil
}

// versionName renders a protocol version as a stable string.
//
// Known versions get their familiar names. An unknown one gets its numeric form
// rather than a guess or a panic, so a future version is reported as a fact
// nobody has to have anticipated.
func versionName(version uint16) string {
	switch version {
	case cryptotls.VersionTLS10:
		return "TLS1.0"
	case cryptotls.VersionTLS11:
		return "TLS1.1"
	case cryptotls.VersionTLS12:
		return "TLS1.2"
	case cryptotls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("%#04x", version)
	}
}

// canonicalDNSNames sorts and deduplicates the certificate's DNS names.
//
// A certificate's name order is an encoding detail, and a report must be
// byte-identical for the same facts.
func canonicalDNSNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := slices.Clone(names)
	slices.Sort(out)
	return slices.Compact(out)
}

// canonicalIPs renders the certificate's IP addresses in one canonical spelling,
// sorted and deduplicated for the same reason.
func canonicalIPs(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}

	addresses := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addresses = append(addresses, addr.Unmap())
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	addresses = slices.Compact(addresses)

	out := make([]string, len(addresses))
	for i, addr := range addresses {
		out[i] = addr.String()
	}
	return out
}
