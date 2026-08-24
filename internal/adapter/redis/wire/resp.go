package wire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// MaxReplySize bounds the bytes svcdoctor will read for one command reply.
//
// # It is svcdoctor's policy, not the protocol's
//
// Redis bounds what a server will *receive* — proto-max-bulk-len, 512 MiB by
// default (redis/src/config.c:3470) — and bounds nothing about what a server may
// send a client. So no number here can be copied from upstream, and a refusal
// under this bound is a statement about svcdoctor rather than an accusation
// against the peer. classifyLimit keeps that distinction in the error type.
//
// # How the value was chosen
//
// ADR 0061 recorded that "8x the largest common value" is not a methodology: a
// real Redpanda instance falsified exactly that reasoning for the SCRAM salt. So
// this is derived twice over, and the measurement is the smaller half of it.
//
// Measured, Phase 7.5, against real servers on the frozen command allowlist:
//
//	Redis 8.2.1   zero-argument HELLO reply   688 bytes
//	Valkey 8.1.1  zero-argument HELLO reply   146 bytes
//	both          PING reply                    7 bytes
//
// The 542-byte difference is entirely the modules array, which is the one
// unbounded field in the reply and the reason ADR 0066 declines to retain it.
//
// The value itself comes from upstream rather than from that measurement:
// PROTO_INLINE_MAX_SIZE is 64 KiB (redis/src/server.h:192), the largest of
// Redis's own single-unit protocol constants, with PROTO_IOBUF_LEN and
// PROTO_REPLY_CHUNK_BYTES both at 16 KiB. Taking the largest of them means the
// bound is anchored to a number Redis itself considers a reasonable ceiling for
// one protocol unit, not to a multiple of what one deployment happened to send.
//
// # Why the number is a safety net rather than the safety mechanism
//
// The property that actually protects svcdoctor is in readBulk and readArray:
// **nothing is ever allocated on a length the peer declared.** A declared bulk
// length above the remaining budget is refused before a byte is allocated, and
// an array grows only as elements genuinely arrive. That holds at any budget, so
// this constant can be generous and carry no interoperability risk. A deployment
// would need roughly 600 modules with long filesystem paths to reach it.
//
// # Costs
//
// Memory: at most this many bytes per reply, on one connection per run.
// CPU: linear in the bytes that actually arrived; a refusal does no more work
// than reading up to the ceiling.
const MaxReplySize = 64 << 10

// maxArrayElements bounds the element count svcdoctor will accept in a declared
// array header.
//
// **It is derived, not chosen.** The smallest legal RESP2 array element is a
// four-byte integer such as ":0\r\n", so an array that could be satisfied inside
// MaxReplySize can hold at most MaxReplySize/4 elements. A declared count above
// this is unsatisfiable within the budget by arithmetic, which is why refusing it
// at the header costs nothing: no legal reply is lost, and the alternative is
// reading a quarter of a megabyte to reach the same refusal.
const maxArrayElements = MaxReplySize / 4

// maxDepth bounds nesting.
//
// **Derived from the frozen command allowlist**, not from headroom. The deepest
// legitimate reply the three allowed commands can produce is HELLO's:
//
//	depth 1  the reply array
//	depth 2  the modules array, which is one of its values
//	depth 3  one module's own array
//
// Nothing in HELLO, AUTH or PING nests further. Four permits exactly one level
// of slack for a field a future server version might add one deeper, and refuses
// anything past it.
//
// The byte budget alone would not cover this. A nesting bomb costs four bytes per
// level, so 64 KiB of "*1\r\n" is sixteen thousand frames of recursion — bounded
// heap and unbounded stack. This bounds the stack.
const maxDepth = 4

// Sentinel errors describing what happened on the wire.
//
// The adapter classifies structurally against these. Matching on message text
// would be a claim that quietly stops being true when an implementation changes
// its wording, and — because Redis interpolates caller-supplied bytes into error
// text — it would risk carrying a byte the peer chose into a report.
var (
	// ErrPeerClosed means the peer closed the connection mid-exchange.
	ErrPeerClosed = errors.New("peer closed the connection during the exchange")

	// ErrMalformedReply means the framing itself was not valid RESP2: an
	// unknown first byte, a length that is not a number, a missing terminator,
	// or a truncated body.
	//
	// **Every RESP3-only first byte lands here.** On a connection that never
	// negotiated RESP3 a map, set, push, attribute, double, big number, verbatim
	// string, boolean or null is not a legal frame, and treating one as legal
	// would be accepting a protocol svcdoctor did not agree to speak.
	ErrMalformedReply = errors.New("redis reply could not be decoded as RESP2")

	// ErrReplyTooLarge means the peer's reply was structurally legal and
	// svcdoctor declined to spend the memory.
	//
	// It is deliberately distinct from ErrMalformedReply. The peer did nothing
	// wrong, and an adapter that collapsed the two would report a svcdoctor
	// resource policy as a defect in the endpoint — the exact truthfulness
	// defect ADR 0061 section 28 corrected for SCRAM.
	ErrReplyTooLarge = errors.New("redis reply exceeds the size svcdoctor will read")

	// ErrUnexpectedReply means the frame decoded but is not a shape this
	// protocol step allows.
	ErrUnexpectedReply = errors.New("redis reply is not valid at this protocol step")

	// ErrInvalidInput means this package was called with something it cannot
	// encode.
	ErrInvalidInput = errors.New("invalid redis wire input")
)

// replyKind is the RESP2 type of one decoded frame.
type replyKind uint8

const (
	kindInvalid replyKind = iota
	kindSimpleString
	kindError
	kindInteger
	kindBulk
	kindArray
)

// reply is one decoded RESP2 frame.
//
// It is unexported, and so is every field. A caller outside this package cannot
// hold a frame, which is what keeps peer-chosen bytes — an error message, a
// module path, a bulk value — from travelling further by accident. The exported
// surface hands back normalized values only.
type reply struct {
	kind    replyKind
	text    string // simple string, or raw error text that never leaves this package
	integer int64
	bulk    []byte
	null    bool
	array   []reply
}

// reader decodes RESP2 frames under a per-reply byte budget.
//
// The budget is reset before each command's reply rather than shared across the
// connection, because the question it answers is "how much will svcdoctor read
// for this one answer", and a long-lived connection reading three small replies
// is not a reason to refuse the third.
type reader struct {
	br        *bufio.Reader
	remaining int
}

func newReader(r io.Reader) *reader {
	// The buffer is deliberately small. It is a read buffer, not the bound: the
	// bound is `remaining`, and sizing this to MaxReplySize would allocate the
	// ceiling for every connection whether or not a peer ever approached it.
	return &reader{br: bufio.NewReaderSize(r, 4096)}
}

// begin starts a new reply and resets the budget.
func (r *reader) begin() { r.remaining = MaxReplySize }

// spend deducts n bytes from the budget, or refuses.
//
// Every read in this file goes through it, so there is one place the accounting
// can be wrong and one place a test has to pin.
func (r *reader) spend(n int) error {
	if n > r.remaining {
		return fmt.Errorf("%w: reply exceeded %d bytes", ErrReplyTooLarge, MaxReplySize)
	}
	r.remaining -= n
	return nil
}

// readLine reads one CRLF-terminated line and returns it without the terminator.
//
// It reads byte by byte against the budget rather than using ReadString, because
// ReadString on a peer that never sends '\n' buffers without limit. This cannot:
// the budget is checked before each byte is kept.
func (r *reader) readLine() (string, error) {
	var line []byte
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return "", translateRead(err)
		}
		if err := r.spend(1); err != nil {
			return "", err
		}
		if b == '\n' {
			if len(line) == 0 || line[len(line)-1] != '\r' {
				return "", fmt.Errorf("%w: line terminator is not CRLF", ErrMalformedReply)
			}
			return string(line[:len(line)-1]), nil
		}
		line = append(line, b)
	}
}

// readReply decodes one frame.
func (r *reader) readReply() (reply, error) { return r.readFrame(1) }

func (r *reader) readFrame(depth int) (reply, error) {
	if depth > maxDepth {
		return reply{}, fmt.Errorf("%w: reply nested deeper than %d", ErrReplyTooLarge, maxDepth)
	}

	prefix, err := r.br.ReadByte()
	if err != nil {
		return reply{}, translateRead(err)
	}
	if err := r.spend(1); err != nil {
		return reply{}, err
	}

	switch prefix {
	case '+':
		line, err := r.readLine()
		if err != nil {
			return reply{}, err
		}
		return reply{kind: kindSimpleString, text: line}, nil

	case '-':
		line, err := r.readLine()
		if err != nil {
			return reply{}, err
		}
		return reply{kind: kindError, text: line}, nil

	case ':':
		line, err := r.readLine()
		if err != nil {
			return reply{}, err
		}
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return reply{}, fmt.Errorf("%w: integer is not a base-10 int64", ErrMalformedReply)
		}
		return reply{kind: kindInteger, integer: n}, nil

	case '$':
		return r.readBulk()

	case '*':
		return r.readArray(depth)

	default:
		// Everything else, including every RESP3-only first byte. See
		// ErrMalformedReply on why RESP3 is not "unsupported" here but invalid.
		return reply{}, fmt.Errorf("%w: unknown first byte %#x", ErrMalformedReply, prefix)
	}
}

// readBulk decodes a bulk string, including the RESP2 null form.
//
// **No allocation happens on the declared length.** The length is compared
// against the remaining budget first, so a peer announcing half a gigabyte is
// refused having caused svcdoctor to allocate nothing at all.
func (r *reader) readBulk() (reply, error) {
	line, err := r.readLine()
	if err != nil {
		return reply{}, err
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return reply{}, fmt.Errorf("%w: bulk length is not an integer", ErrMalformedReply)
	}
	if n == -1 {
		return reply{kind: kindBulk, null: true}, nil
	}
	if n < 0 {
		return reply{}, fmt.Errorf("%w: negative bulk length %d", ErrMalformedReply, n)
	}
	// The body plus its CRLF must fit in what is left. Checked before the make.
	if err := r.spend(n + 2); err != nil {
		return reply{}, err
	}

	body := make([]byte, n+2)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return reply{}, translateRead(err)
	}
	if body[n] != '\r' || body[n+1] != '\n' {
		return reply{}, fmt.Errorf("%w: bulk body is not CRLF terminated", ErrMalformedReply)
	}
	return reply{kind: kindBulk, bulk: body[:n]}, nil
}

// readArray decodes an array, including the RESP2 null form.
//
// **The element slice is never preallocated from the declared count.** It grows
// as elements genuinely arrive, so a peer announcing a huge array pays for every
// element it actually sends and svcdoctor allocates nothing for the ones it does
// not.
func (r *reader) readArray(depth int) (reply, error) {
	line, err := r.readLine()
	if err != nil {
		return reply{}, err
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return reply{}, fmt.Errorf("%w: array length is not an integer", ErrMalformedReply)
	}
	if n == -1 {
		return reply{kind: kindArray, null: true}, nil
	}
	if n < 0 {
		return reply{}, fmt.Errorf("%w: negative array length %d", ErrMalformedReply, n)
	}
	if n > maxArrayElements {
		return reply{}, fmt.Errorf("%w: array declares %d elements, above %d",
			ErrReplyTooLarge, n, maxArrayElements)
	}

	out := reply{kind: kindArray}
	for i := 0; i < n; i++ {
		element, err := r.readFrame(depth + 1)
		if err != nil {
			return reply{}, err
		}
		out.array = append(out.array, element)
	}
	return out, nil
}

// translateRead turns a read error into this package's vocabulary.
//
// io.EOF and io.ErrUnexpectedEOF both mean the peer stopped talking. Everything
// else — a deadline, a reset, a cancelled context — is returned as it arrived so
// that the adapter can tell a local budget from a remote close.
func translateRead(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrPeerClosed, err)
	}
	return err
}
