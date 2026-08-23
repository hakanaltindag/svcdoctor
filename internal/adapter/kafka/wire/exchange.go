package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"
)

const (
	// clientID identifies svcdoctor in the broker's logs. It is fixed rather
	// than configurable: a diagnostic tool should be recognizable, and nothing
	// yet needs to pretend to be something else.
	clientID = "svcdoctor"

	// maxResponseSize bounds what a peer can make svcdoctor allocate. A peer
	// that is not Kafka usually announces a nonsensical size here, which is how
	// ErrNotKafka is recognized.
	maxResponseSize = 8 << 20
)

// Correlation identifiers, one per request kind.
//
// Exactly one request is ever in flight, so these do not need to be unique over
// time and are deliberately not generated: a counter or a clock would make the
// bytes svcdoctor sends depend on how many exchanges preceded them.
//
// They differ per request kind for one reason. A connection now carries several
// exchanges in sequence, so "the response I am reading answers the request I
// just sent" is a claim worth being able to check. A stale ApiVersions response
// read while a handshake is expected fails the comparison instead of being
// decoded as a handshake.
const (
	correlationAPIVersions      uint32 = 1
	correlationSASLHandshake    uint32 = 2
	correlationSASLAuthenticate uint32 = 3
	correlationMetadata         uint32 = 4
)

// Sentinel errors describing what was observed on the wire.
//
// They exist so that the layer above can classify structurally. Matching on
// error text would be a claim that quietly stops being true when a library or a
// platform changes its wording.
var (
	// ErrPeerClosed means the peer closed the connection during the exchange.
	ErrPeerClosed = errors.New("peer closed the connection during the exchange")

	// ErrNotKafka means the peer answered with something that is not Kafka
	// framing at all.
	ErrNotKafka = errors.New("peer response is not kafka framing")

	// ErrMalformedResponse means the framing was plausible but the response
	// could not be decoded, or answered a different request.
	ErrMalformedResponse = errors.New("kafka response could not be decoded")
)

// exchange sends one request over conn and decodes the response into resp.
//
// It is the whole of svcdoctor's Kafka framing, in one place, so that every
// request kind is written and read the same way. The connection is borrowed,
// not owned: this never closes it, because whether a connection survives its
// exchange is an ownership decision for the caller. Deadlines set here are
// cleared before returning, so a connection handed on afterwards behaves as
// though nothing happened to it.
//
// Both messages must be non-flexible at the version set on them. A flexible
// response carries tagged fields in its header, which this reader does not
// consume, so accepting one would misparse the body one byte at a time. The
// guard is here rather than in a comment because the mistake is silent.
func exchange(
	ctx context.Context, conn net.Conn, correlationID uint32, req kmsg.Request, resp kmsg.Response,
) error {
	if conn == nil {
		return errors.New("wire: connection must not be nil")
	}
	if req.IsFlexible() || resp.IsFlexible() {
		return fmt.Errorf("wire: flexible message %d is not supported by this framing", req.Key())
	}

	release := bindDeadline(ctx, conn)
	defer release()

	if err := writeRequest(conn, correlationID, req); err != nil {
		return err
	}
	return readResponse(conn, correlationID, resp)
}

// bindDeadline makes the caller's context able to interrupt blocking I/O.
//
// A context alone cannot stop a Read that is already waiting, so the context's
// deadline is applied to the socket and a watcher expires it if the context ends
// first. The returned function clears both, which is what leaves the connection
// clean for whoever uses it next.
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

// writeRequest encodes and sends the request.
//
// kmsg produces the entire message, length prefix and request header included,
// so nothing about the protocol's shape is written by hand here.
func writeRequest(conn net.Conn, correlationID uint32, req kmsg.Request) error {
	formatter := kmsg.NewRequestFormatter(kmsg.FormatterClientID(clientID))

	//nolint:gosec // G115: the identifier is one of this package's own constants,
	// and the protocol field is a signed int32 that kmsg writes as one.
	encoded := formatter.AppendRequest(nil, req, int32(correlationID))

	if _, err := conn.Write(encoded); err != nil {
		return writeError(err)
	}
	return nil
}

// readResponse reads one framed response and decodes it.
func readResponse(conn net.Conn, correlationID uint32, resp kmsg.Response) error {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return readError(err)
	}

	// Kafka sizes are signed 32-bit and always positive, so anything with the
	// sign bit set is not a Kafka frame at all. Checking that before converting
	// keeps the decode honest about what the wire actually allows.
	announced := binary.BigEndian.Uint32(sizeBuf[:])
	if announced > math.MaxInt32 {
		return fmt.Errorf("%w: announced a negative response size", ErrNotKafka)
	}
	size := int64(announced)
	if size < 4 || size > maxResponseSize {
		// A peer speaking anything else — HTTP, TLS on a plaintext port, a
		// greeting banner — announces a length here that Kafka never would.
		return fmt.Errorf("%w: announced response size %d", ErrNotKafka, size)
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return readError(err)
	}

	// Every response this package reads uses header v0, so the body starts with
	// the correlation identifier and nothing else. The comparison stays in
	// unsigned space: the identifier is an opaque echo here, and reinterpreting
	// its sign would add a conversion without adding meaning.
	if echoed := binary.BigEndian.Uint32(body[:4]); echoed != correlationID {
		return fmt.Errorf(
			"%w: response carries correlation id %d", ErrMalformedResponse, echoed)
	}

	if err := resp.ReadFrom(body[4:]); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	return nil
}

// readError and writeError name what happened on the socket.
//
// An end of file mid-exchange is the peer hanging up, which is a different fact
// from a decoding failure: one says the peer stopped talking, the other says it
// said something svcdoctor could not read.
func readError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrPeerClosed, err)
	}
	return err
}

func writeError(err error) error {
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("%w: %w", ErrPeerClosed, err)
	}
	return err
}

// errNew and errorIs are thin aliases so that this package's sentinel
// declarations and error comparisons read the same way in every file without
// each one importing errors separately.
func errNew(text string) error { return errors.New(text) }

func errorIs(err, target error) bool { return errors.Is(err, target) }
