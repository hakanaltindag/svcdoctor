package wire

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/sasl/scram"
)

// MaxMessageSize bounds the body of one server message svcdoctor will read.
//
// PostgreSQL's own limit is far larger, so this is svcdoctor's bound and not the
// protocol's: it exists so that a hostile or broken peer cannot make a diagnostic
// tool allocate an arbitrary amount of memory by announcing a length.
//
// One mebibyte is generous for everything the implemented state machine reads. A
// startup-phase message is tens of bytes: an ErrorResponse, an authentication
// request, a SASL mechanism list. The largest thing a later phase would read is a
// ParameterStatus, which is also tiny.
//
// **Reopen when a phase reads query results.** Row data has no comparable bound
// and would need this reconsidered on its own merits rather than raised quietly.
// ADR 0036 settles no value here because none is protocol-semantic; this is an
// implementation safety bound, and that is why it is a constant with a stated
// reason rather than a decision record.
const MaxMessageSize = 1 << 20

// Sentinel errors describing what was observed on the wire.
//
// They exist so the adapter can classify structurally. Matching on error text
// would be a claim that quietly stops being true when a platform changes its
// wording, and it would risk carrying a byte the peer chose into a report.
var (
	// ErrPeerClosed means the peer closed the connection mid-exchange.
	ErrPeerClosed = errors.New("peer closed the connection during the exchange")

	// ErrMalformedMessage means the framing itself was not valid: an impossible
	// length, a truncated body, or a field list with no terminator.
	ErrMalformedMessage = errors.New("postgres message could not be decoded")

	// ErrFrameTooLarge means the peer announced a body larger than
	// MaxMessageSize. It is kept distinct from ErrMalformedMessage because the
	// length was structurally legal and svcdoctor refused it, which is a
	// statement about svcdoctor rather than about the peer.
	ErrFrameTooLarge = errors.New("postgres message exceeds the readable size")

	// ErrUnexpectedResponse means the peer answered in a way the protocol does
	// not allow at this point. It covers a first byte to SSLRequest that is not
	// S, N or E.
	ErrUnexpectedResponse = errors.New("peer response is not valid at this protocol step")

	// ErrSurplusBytes means the peer sent more than the single byte the SSL
	// negotiation permits before the TLS handshake. See readSSLResponse.
	ErrSurplusBytes = errors.New("peer sent surplus bytes before the TLS handshake")

	// ErrInvalidInput means this package was called with something it cannot
	// encode, such as a startup parameter containing a NUL byte.
	ErrInvalidInput = errors.New("invalid postgres wire input")

	// ErrPasswordUnsupported means the credential contains a character
	// svcdoctor cannot prepare for SCRAM.
	//
	// It is a statement about svcdoctor and never about the peer: nothing was
	// sent, so the peer expressed no opinion. PostgreSQL applies SASLprep to
	// passwords and svcdoctor implements only the printable-ASCII range over
	// which SASLprep provably changes nothing. See printableASCII and ADR 0038
	// section 11.
	ErrPasswordUnsupported = errors.New("password is outside the range svcdoctor can prepare for SCRAM")

	// ErrLocalDerivation means svcdoctor's own SCRAM derivation did not
	// produce usable key material.
	//
	// It covers a missing derivation callback, a callback that failed, key
	// material of the wrong length, and an exchange driven out of order. Every
	// one is a defect in svcdoctor rather than anything the peer did, which is
	// why it classifies as a capability gap and never as a target failure.
	//
	// **None of them is reachable from this package's own call path**: the
	// callback is a literal, the exchange is driven linearly, and PBKDF2 is
	// asked for exactly sha256.Size bytes. It exists so that if one ever
	// becomes reachable, it arrives as "svcdoctor could not do this" instead of
	// as an accusation against the server.
	ErrLocalDerivation = errors.New("svcdoctor could not complete its own SCRAM derivation")
)

// SCRAM sentinels that are aliases of the shared core's.
//
// # Why these three are aliases and two others are not
//
// internal/adapter/postgres/authenticate.go classifies with errors.Is against
// these exact values, so aliasing keeps identity — and therefore every existing
// FailureClass — unchanged by the Phase 6.2 extraction. No test moved, no
// mapping moved, and a caller cannot tell the difference.
//
// ErrMalformedMessage and ErrUnexpectedResponse are deliberately **not**
// aliased. Both already exist above with PostgreSQL *framing* meanings, and
// pointing them at the core's equivalents would collapse two distinct meanings
// onto one identity: "this postgres frame could not be decoded" and "this SCRAM
// attribute list could not be decoded" would become the same error. The
// classifier does not match either individually, so translateSCRAM converts
// them at the boundary instead. See ADR 0056 section 8.
var (
	// ErrIterationsUnsupported means the peer named a PBKDF2 iteration count
	// above MaxSCRAMIterations.
	//
	// A statement about svcdoctor: the count is legal protocol, and svcdoctor
	// declines to spend the CPU. Kept distinct from ErrMalformedMessage because
	// the value was structurally valid.
	ErrIterationsUnsupported = scram.ErrIterationsUnsupported

	// ErrServerSignatureMismatch means the server's SCRAM signature did not
	// match the one derived locally, so the peer did not prove knowledge of the
	// credential.
	//
	// The exchange is unsuccessful from that point on, whatever the peer sends
	// next — including AuthenticationOk.
	ErrServerSignatureMismatch = scram.ErrServerSignatureMismatch

	// ErrSCRAMRejected means the server ended the SCRAM exchange with an error
	// token naming the credential.
	//
	// The token itself never leaves the shared core's comparison.
	ErrSCRAMRejected = scram.ErrRejected

	// ErrSCRAMParametersUnsupported means the server's SCRAM message was legal
	// and larger than svcdoctor's defensive resource policy reads.
	//
	// **A statement about svcdoctor, never about the server**, and the same
	// claim ErrIterationsUnsupported makes about a legal iteration count: RFC
	// 5802 and RFC 7677 set no maximum on a salt, a nonce, an attribute list or
	// a message, so a value above one of svcdoctor's ceilings is valid protocol
	// svcdoctor declines to process.
	//
	// It is distinct from ErrFrameTooLarge, which this previously reused.
	// ErrFrameTooLarge is a *framing* fact about a PostgreSQL message header and
	// classifies as a malformed response; a SCRAM field above a core ceiling is
	// neither framing nor malformed, and reporting it that way blamed the peer
	// for svcdoctor's policy. See ADR 0061 §19.
	ErrSCRAMParametersUnsupported = errors.New(
		"peer SCRAM parameters exceed the size svcdoctor reads")
)

// translateSCRAM maps a shared-core error into this package's vocabulary.
//
// The three aliased sentinels pass through untouched — they are the same values.
// The core's framing errors become this package's own, so that a caller
// classifying a PostgreSQL exchange keeps seeing PostgreSQL errors. The local
// faults collapse into ErrLocalDerivation.
//
// Nothing here wraps: every returned value is a package-level sentinel with
// fixed text, so no byte the peer chose can travel out through an error.
func translateSCRAM(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, scram.ErrIterationsUnsupported),
		errors.Is(err, scram.ErrServerSignatureMismatch),
		errors.Is(err, scram.ErrRejected):
		return err
	case errors.Is(err, scram.ErrMalformedMessage):
		return ErrMalformedMessage
	case errors.Is(err, scram.ErrUnexpectedResponse):
		return ErrUnexpectedResponse
	case errors.Is(err, scram.ErrMessageTooLarge):
		// The core refused a peer field larger than it reads.
		//
		// This used to return ErrFrameTooLarge on the reasoning that both mean
		// "structurally legal, and svcdoctor declined it". The claim is right
		// and the sentinel was wrong: ErrFrameTooLarge classifies as
		// PROTOCOL_MALFORMED_RESPONSE, so the reuse turned a svcdoctor policy
		// decision into an accusation that the peer sent something undecodable.
		// A legal 130-byte Redpanda salt is the measured counterexample.
		// See ADR 0061 §19.
		return ErrSCRAMParametersUnsupported
	case errors.Is(err, scram.ErrUsernameUnsupported),
		errors.Is(err, scram.ErrNoDerivation),
		errors.Is(err, scram.ErrDerivationFailed),
		errors.Is(err, scram.ErrDerivedKeyLength),
		errors.Is(err, scram.ErrWrongStep):
		return ErrLocalDerivation
	default:
		return err
	}
}

// bindDeadline makes the caller's context able to interrupt blocking I/O, and
// leaves the connection clean afterwards.
//
// A context alone cannot stop a Read that is already waiting, so the context's
// deadline is applied to the socket and a watcher expires it if the context ends
// first. The returned function stops the watcher and clears the deadline.
//
// Clearing is load-bearing here rather than tidy. The connection this runs over
// is handed to a TLS handshake and then to a later protocol step; a deadline
// surviving the call would expire inside somebody else's exchange and be
// misattributed to them. internal/adapter/kafka/wire makes the same arrangement
// for the same reason, and the two are deliberately separate copies: a shared
// helper would be a generic transport utility living in a service package.
//
// # Release waits for the watcher, and that is not tidiness
//
// An earlier version returned as soon as it had closed `done` and cleared the
// deadline. That left a race with teeth: if the caller's context was cancelled at
// about the same moment — which is exactly what a `defer cancel()` on a derived
// context does — the watcher goroutine could find **both** channels ready, pick
// `ctx.Done()`, and set an expired deadline *after* release had cleared it. The
// connection was then permanently unusable, and nothing afterwards would clear
// it, because release had already run.
//
// It surfaced in Phase 4.5b, on the one path where a write follows a bounded read
// on the same socket: the Terminate that closes an established session failed with
// `i/o timeout` against a peer that was plainly still listening. Before that path
// existed the bug was invisible, because every other caller either closed the
// connection or handed it straight on.
//
// Waiting for the watcher to exit before clearing makes the documented invariant
// — *on return, this call has left no deadline behind* — actually true, whatever
// order the runtime chose. The wait is a goroutine exit, not I/O.
//
// **The guard is TestHealthySessionSendsTerminate**, in the adapter package: it
// drives the real path and fails deterministically against the broken version. A
// unit test at this level was written and then deleted, because it could not be
// made to reproduce — the watcher is already parked in its select by the time
// release runs, so a sequential loop, and even thirty-two concurrent ones, passed
// against code that was demonstrably wrong. A test that cannot fail is not
// coverage, and leaving it would have claimed protection this level cannot give.
//
// internal/adapter/kafka/wire has the same shape and has not been changed here:
// no Kafka path writes to a connection after a bounded read, so nothing triggers
// it there. Recorded rather than fixed silently in a phase that does not own it.
func bindDeadline(ctx context.Context, conn net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			// Expiring the deadline unblocks whichever side is waiting.
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	return func() {
		close(done)
		// The watcher can no longer touch the connection once this returns, so
		// the clear below is the final word on its deadline.
		<-stopped
		_ = conn.SetDeadline(time.Time{})
	}
}

// readFull fills buf, translating a truncated read into the sentinel that says
// the peer stopped talking.
//
// io.ErrUnexpectedEOF and io.EOF both mean the same thing to a caller here: the
// exchange did not finish because the other end went away. A deadline error is
// passed through untouched so the adapter can attribute it to the right side.
func readFull(conn net.Conn, buf []byte) error {
	if _, err := io.ReadFull(conn, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrPeerClosed
		}
		return err
	}
	return nil
}

// writeAll writes every byte of buf.
//
// net.Conn.Write already reports a short write as an error, so this exists to
// name that contract rather than to loop: a partial write with a nil error would
// be a violation of io.Writer, and treating it as one here would hide it.
func writeAll(conn net.Conn, buf []byte) error {
	n, err := conn.Write(buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ErrPeerClosed
		}
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}
