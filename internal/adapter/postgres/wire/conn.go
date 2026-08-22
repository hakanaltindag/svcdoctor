package wire

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
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

	// ErrIterationsUnsupported means the peer named a PBKDF2 iteration count
	// above MaxSCRAMIterations.
	//
	// Also a statement about svcdoctor: the count is legal protocol, and
	// svcdoctor declines to spend the CPU. It is kept distinct from
	// ErrMalformedMessage because the value was structurally valid.
	ErrIterationsUnsupported = errors.New("peer demanded more SCRAM iterations than svcdoctor performs")

	// ErrServerSignatureMismatch means the server's SCRAM signature did not
	// match the one derived locally, so the peer did not prove knowledge of the
	// credential.
	//
	// The exchange is unsuccessful from that point on, whatever the peer sends
	// next — including AuthenticationOk.
	ErrServerSignatureMismatch = errors.New("server did not prove knowledge of the credential")

	// ErrSCRAMRejected means the server ended the SCRAM exchange with an error
	// token naming the credential.
	//
	// The token itself never leaves the comparison that produced this sentinel.
	ErrSCRAMRejected = errors.New("peer rejected the SCRAM credential")
)

// bindDeadline makes the caller's context able to interrupt blocking I/O, and
// leaves the connection clean afterwards.
//
// A context alone cannot stop a Read that is already waiting, so the context's
// deadline is applied to the socket and a watcher expires it if the context ends
// first. The returned function clears both.
//
// Clearing is load-bearing here rather than tidy. The connection this runs over
// is handed to a TLS handshake and then to a later protocol step; a deadline
// surviving the call would expire inside somebody else's exchange and be
// misattributed to them. internal/adapter/kafka/wire makes the same arrangement
// for the same reason, and the two are deliberately separate copies: a shared
// helper would be a generic transport utility living in a service package.
func bindDeadline(ctx context.Context, conn net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Expiring the deadline unblocks whichever side is waiting.
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	return func() {
		close(done)
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
