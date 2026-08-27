package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ProtocolHeader is the eight bytes svcdoctor sends first, and the only eight it
// ever sends first.
//
// AMQP 0-9-1 and nothing else (ADR 0067 section 2). A peer that will not speak
// it answers with a protocol header of its own and closes; that is a refusal
// rather than an instruction, and this package reports it as one.
var ProtocolHeader = []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

// Frame layout and the bounds that govern it, all frozen by ADR 0070 section 5.
//
// Every one of these is a value the protocol or an implementation fixes. None is
// a multiple of an observed size: ADR 0061 exists because a bound justified that
// way was falsified by a real broker, and ADR 0070 section 6 forbids tightening
// the ceiling toward the 328-712 byte frames Phase 8.0C measured.
const (
	// frameOverhead is type(1) + channel(2) + size(4) + end(1).
	frameOverhead = 8
	// frameHeaderLen is the part read before any payload byte is allocated.
	frameHeaderLen = 7
	// frameEnd terminates every frame. Anything else means lost sync.
	frameEnd = 0xCE

	// frameTypeMethod is the only frame type BASIC exchanges. Header, body and
	// heartbeat frames are never sent and never expected: no content crosses
	// this connection and heartbeats are disabled (ADR 0070 section 4).
	frameTypeMethod = 1

	// preTuneFrameMax is the ceiling before Connection.Tune-Ok, and it is
	// RabbitMQ's own `initial_frame_max` default. A peer exceeding it breaks the
	// AMQP frame-min-size contract and its own default clients.
	preTuneFrameMax    = 8192
	preTunePayloadMax  = preTuneFrameMax - frameOverhead // 8184
	postTuneFrameMax   = 8192                            // what svcdoctor advertises
	postTunePayloadMax = postTuneFrameMax - frameOverhead

	// specFrameMinSize is the AMQP 0-9-1 frame-min-size constant and svcdoctor's
	// local floor. A negotiation that would land below it is refused locally
	// rather than sent (ADR 0070 section 2).
	specFrameMinSize = 4096

	// maxReplyText is the shortstr maximum, which is also the protocol's own
	// bound on Connection.Close.reply-text. A longer field is malformed.
	maxReplyText = 255

	// MaxVHostBytes is the `path` domain's assert. Operator input above it is
	// refused before a connection is opened.
	MaxVHostBytes = 127
)

// classConnection is the only AMQP class this package can encode.
//
// It is deliberately not a parameter anywhere. See connectionMethod.
const classConnection uint16 = 10

// connectionMethod is the closed set of methods svcdoctor may send.
//
// **This type is the structural guard.** encodeMethod takes one of these, so a
// method outside the connection class cannot be expressed: there is no channel
// id, no class parameter and no escape hatch. Adding Channel.Open would require
// changing this type's meaning, which is a visible edit rather than a new call.
type connectionMethod uint16

const (
	mStartOk connectionMethod = 11
	mTuneOk  connectionMethod = 31
	mOpen    connectionMethod = 40
	mClose   connectionMethod = 50
	mCloseOk connectionMethod = 51
)

// Inbound method ids. These are compared against, never encoded.
const (
	inStart  uint16 = 10
	inSecure uint16 = 20
	inTune   uint16 = 30
	inOpenOk uint16 = 41
	inClose  uint16 = 50
	inCloseK uint16 = 51
)

// encodeMethod builds one method frame on channel 0.
//
// Channel 0 is the connection's own channel and the only one BASIC uses. The
// class is the constant above rather than an argument, which is what makes a
// non-connection method unrepresentable.
func encodeMethod(m connectionMethod, payload []byte) []byte {
	body := make([]byte, 0, 4+len(payload))
	body = binary.BigEndian.AppendUint16(body, classConnection)
	body = binary.BigEndian.AppendUint16(body, uint16(m))
	body = append(body, payload...)

	out := make([]byte, 0, frameOverhead+len(body))
	out = append(out, frameTypeMethod)
	out = binary.BigEndian.AppendUint16(out, 0) // channel 0
	//nolint:gosec // G115: body is this package's own buffer, and the largest
	// method it builds is a Start-Ok bounded by the credential's own length.
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	out = append(out, frameEnd)
	return out
}

// frame is one decoded method frame. The payload is this package's own buffer.
type frame struct {
	classID  uint16
	methodID uint16
	// fields is the method payload after the four class/method bytes.
	fields []byte
}

// reader decodes frames under a ceiling that the caller raises exactly once.
type reader struct {
	src io.Reader
	// ceiling bounds the declared payload size. It starts at the pre-Tune value
	// and is raised to the negotiated one after Tune-Ok, never lowered and never
	// raised above postTunePayloadMax.
	ceiling uint32
	hdr     [frameHeaderLen]byte
	end     [1]byte
}

func newReader(src io.Reader) *reader {
	return &reader{src: src, ceiling: preTunePayloadMax}
}

// negotiated raises the ceiling to the value svcdoctor advertised in Tune-Ok.
//
// It refuses to raise it above what this package will ever advertise, so a
// caller cannot widen the parser by passing a peer's number through.
func (r *reader) negotiated(payloadMax uint32) {
	if payloadMax > postTunePayloadMax {
		payloadMax = postTunePayloadMax
	}
	if payloadMax > r.ceiling {
		r.ceiling = payloadMax
	}
}

// readFrame reads exactly one frame.
//
// # The size is validated before anything is allocated
//
// The seven-byte header is read into a fixed array on the reader. The declared
// size is checked against the ceiling *before* the payload buffer exists, so a
// peer declaring four gibibytes causes a refusal rather than an allocation. That
// ordering is the whole of the defence and is asserted by a test that would fail
// if the make moved above the check.
func (r *reader) readFrame() (frame, error) {
	if _, err := io.ReadFull(r.src, r.hdr[:]); err != nil {
		return frame{}, readErr(err)
	}

	ftype := r.hdr[0]
	channel := binary.BigEndian.Uint16(r.hdr[1:3])
	size := binary.BigEndian.Uint32(r.hdr[3:7])

	// Refuse before allocating. Order matters more than any single bound here.
	if size > r.ceiling {
		return frame{}, fmt.Errorf("%w: frame payload %d exceeds the %d byte ceiling",
			ErrMalformedFrame, size, r.ceiling)
	}
	if ftype != frameTypeMethod {
		return frame{}, fmt.Errorf("%w: frame type %d is not a method frame",
			ErrUnexpectedFrame, ftype)
	}
	if channel != 0 {
		return frame{}, fmt.Errorf("%w: method frame arrived on channel %d",
			ErrUnexpectedFrame, channel)
	}
	if size < 4 {
		return frame{}, fmt.Errorf("%w: method frame payload %d is shorter than a class and method id",
			ErrMalformedFrame, size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r.src, payload); err != nil {
		return frame{}, readErr(err)
	}
	if _, err := io.ReadFull(r.src, r.end[:]); err != nil {
		return frame{}, readErr(err)
	}
	if r.end[0] != frameEnd {
		return frame{}, fmt.Errorf("%w: frame-end byte was 0x%02x", ErrMalformedFrame, r.end[0])
	}

	return frame{
		classID:  binary.BigEndian.Uint16(payload[0:2]),
		methodID: binary.BigEndian.Uint16(payload[2:4]),
		fields:   payload[4:],
	}, nil
}

// readErr normalizes an I/O failure into this package's vocabulary.
//
// A peer that closes mid-exchange and a peer that stops answering are different
// facts and stay different: ErrPeerClosed is a statement about the peer, and a
// deadline is the caller's own budget, which the adapter turns into an execution
// class rather than a target failure.
func readErr(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: %v", ErrPeerClosed, err)
	default:
		return err
	}
}

// --- connection -------------------------------------------------------------

// Conn drives the frozen journey over a connection somebody else established.
//
// It holds the vhost and username the run was given, because Connection.Close
// normalization renders its candidates from those values rather than parsing the
// peer's text (ADR 0069 section 3).
type Conn struct {
	conn net.Conn
	rd   *reader

	vhost    string
	username string
}

// NewConn wraps a live connection. It does not dial and does not own the socket.
func NewConn(conn net.Conn, vhost, username string) *Conn {
	return &Conn{conn: conn, rd: newReader(conn), vhost: vhost, username: username}
}

// exchange writes zero or more bytes and reads exactly one frame.
func (c *Conn) exchange(ctx context.Context, timeout time.Duration, out []byte) (frame, error) {
	ctx, cancel := withStepTimeout(ctx, timeout)
	defer cancel()

	release := bindDeadline(ctx, c.conn)
	defer release()

	if len(out) > 0 {
		if _, err := c.conn.Write(out); err != nil {
			return frame{}, err
		}
	}
	return c.rd.readFrame()
}

// send writes without expecting a reply. Used for Tune-Ok, which has none.
func (c *Conn) send(ctx context.Context, timeout time.Duration, out []byte) error {
	ctx, cancel := withStepTimeout(ctx, timeout)
	defer cancel()

	release := bindDeadline(ctx, c.conn)
	defer release()

	_, err := c.conn.Write(out)
	return err
}

// withStepTimeout narrows a context by the caller's per-step budget.
//
// A zero timeout means the caller's own context is the only bound, which is the
// contract every other adapter's step timeout has.
//
// # The floor is not enforced here, and that is deliberate
//
// ADR 0070 section 8 requires a per-step timeout above three seconds, because
// several RabbitMQ refusal paths hold the socket open for exactly that long on
// purpose. Enforcing it here would silently override an operator's explicit
// --step-timeout; the CLI validates it instead, where a refusal can be explained.
func withStepTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// bindDeadline mirrors the PostgreSQL and Redis wire helpers, and for the same
// reason: a context that ends while a read is parked must unblock the read, and
// the call must leave no deadline behind on a connection it hands on.
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
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	return func() {
		close(done)
		<-stopped
		_ = conn.SetDeadline(time.Time{})
	}
}
