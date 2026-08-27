package wire

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// ServerStart is what Connection.Start established.
//
// Every field is a **peer assertion**, never proof of identity. A proxy can send
// any of them, and Phase 8.0C measured LavinMQ omitting three of RabbitMQ's six
// properties entirely. ADR 0069 section 8 forbids any of them becoming a finding.
type ServerStart struct {
	VersionMajor byte
	VersionMinor byte

	// Product, Version, Platform and ClusterName are the four top-level string
	// properties svcdoctor extracts. Every other property is skipped by declared
	// length without being entered (ADR 0070 section 5.1). An absent property is
	// the empty string, which is a real observation rather than a gap.
	Product     string
	Version     string
	Platform    string
	ClusterName string

	// Mechanisms is the **recognized subset** of the peer's mechanism list,
	// sorted and space-joined.
	//
	// It is deliberately not the peer's own bytes. The list is a peer-controlled
	// longstr bounded only by the frame, and copying it into evidence would put
	// up to eight kibibytes of peer-chosen text in a report for no diagnostic
	// gain. Recording the intersection with a closed set answers the only
	// question BASIC asks — which mechanisms svcdoctor could have used — and
	// carries no peer byte, which is ADR 0066's rule applied to a second field.
	Mechanisms string

	// PlainOffered decides whether the run may proceed to authentication.
	PlainOffered bool
	// AnonymousOffered is recorded because an endpoint advertising ANONYMOUS
	// will let a remote client attempt a guest login with no credential
	// configured anywhere. It is an observation and never a finding: that is a
	// hardening judgement, and BASIC diagnoses reachability (ADR 0069 section 8).
	AnonymousOffered bool
}

// knownMechanisms is the closed set svcdoctor recognizes by name.
//
// Membership is the whole of the rule. A mechanism outside it is not reported,
// which is truthful — svcdoctor did not recognize it — and means no peer-chosen
// token can reach a report.
var knownMechanisms = []string{"PLAIN", "AMQPLAIN", "ANONYMOUS", "EXTERNAL", "RABBIT-CR-DEMO"}

// containsToken reports whether the space-delimited list holds exactly name.
//
// Token equality, not substring containment: a peer offering `PLAINTEXT-ONLY`
// does not offer `PLAIN`, and `strings.Contains` would say it does.
func containsToken(list, name string) bool {
	for _, tok := range strings.Fields(list) {
		if tok == name {
			return true
		}
	}
	return false
}

// Start sends the protocol header and reads Connection.Start.
//
// # A returned protocol header is a refusal, not an instruction
//
// RabbitMQ answers an unrecognized header with eight bytes of its own and closes
// — and its default fallback is the AMQP 1.0 SASL header even for input that is
// not AMQP at all. Reading that as "the peer prefers 1.0" would be inventing an
// identity. It reaches ErrNotAMQP091 and nothing more is claimed.
func (c *Conn) Start(ctx context.Context, timeout time.Duration) (ServerStart, error) {
	f, err := c.exchange(ctx, timeout, ProtocolHeader)
	if err != nil {
		// A peer that answers a protocol header with a protocol header produces
		// a frame decode failure, because eight bytes beginning "AMQP" are not a
		// method frame. Distinguish it so the adapter can say which happened.
		if peerRefusedProtocol(err) {
			return ServerStart{}, fmt.Errorf("%w: %v", ErrNotAMQP091, err)
		}
		return ServerStart{}, err
	}
	if f.classID != classConnection || f.methodID != inStart {
		return ServerStart{}, fmt.Errorf("%w: expected connection.start, got %d/%d",
			ErrNotAMQP091, f.classID, f.methodID)
	}

	cur := &cursor{b: f.fields}
	major, err := cur.u8()
	if err != nil {
		return ServerStart{}, err
	}
	minor, err := cur.u8()
	if err != nil {
		return ServerStart{}, err
	}
	tableLen, err := cur.u32()
	if err != nil {
		return ServerStart{}, err
	}
	props, err := walkTopLevelTable(cur, int(tableLen))
	if err != nil {
		return ServerStart{}, err
	}
	mechanisms, err := cur.longstr()
	if err != nil {
		return ServerStart{}, err
	}
	if _, err := cur.longstr(); err != nil { // locales, read and discarded
		return ServerStart{}, err
	}

	var recognized []string
	for _, name := range knownMechanisms {
		if containsToken(mechanisms, name) {
			recognized = append(recognized, name)
		}
	}
	sort.Strings(recognized)

	return ServerStart{
		VersionMajor:     major,
		VersionMinor:     minor,
		Product:          props["product"],
		Version:          props["version"],
		Platform:         props["platform"],
		ClusterName:      props["cluster_name"],
		Mechanisms:       strings.Join(recognized, " "),
		PlainOffered:     containsToken(mechanisms, "PLAIN"),
		AnonymousOffered: containsToken(mechanisms, "ANONYMOUS"),
	}, nil
}

// peerRefusedProtocol reports whether a failure looks like an eight-byte
// protocol-header refusal rather than a transport problem.
func peerRefusedProtocol(err error) bool {
	return errorsIs(err, ErrMalformedFrame) || errorsIs(err, ErrUnexpectedFrame)
}

// Tune is the negotiation window the peer offered.
type Tune struct {
	ChannelMax uint16
	FrameMax   uint32
	Heartbeat  uint16
}

// Selected is what svcdoctor answered with.
type Selected struct {
	ChannelMax uint16
	FrameMax   uint32
	Heartbeat  uint16
}

// SendStartOk sends the one credential-bearing frame and reads its answer.
//
// # This is the only Reveal in the RabbitMQ adapter
//
// The secret is revealed immediately before the bytes that put it on the socket,
// is not stored, not logged, not returned and not placed in any error. No
// erasure is claimed: encoding copies the bytes and Go strings are immutable, so
// a Zero call here would contradict internal/security/doc.go.
//
// # It is called once per run by construction
//
// Not by a counter here, which could be reset, but because
// internal/adapter/rabbitmq.Authenticate is the only caller, takes one
// connection, holds no loop and has no reconnect path. ADR 0068 section 5.
//
// # Connection.Tune is the success signal
//
// RabbitMQ never acknowledges authentication. The `{ok, User}` branch of its
// reader is the only one that sends Tune, so receipt of Tune *is* the proof —
// which is why ADR 0067 section 4.1 makes Tune's values attributes of the
// authentication node rather than a node of their own.
func (c *Conn) SendStartOk(
	ctx context.Context, timeout time.Duration, username string, secret security.Secret,
) (Tune, error) {
	if secret.IsEmpty() {
		// Unreachable behind the adapter, which does not call this without a
		// credential. Refusing rather than sending an empty password keeps it
		// that way: an empty password is an attempt the endpoint would count.
		return Tune{}, fmt.Errorf("%w: PLAIN requires a credential", ErrInvalidInput)
	}
	if strings.ContainsRune(username, 0) {
		return Tune{}, fmt.Errorf("%w: a username may not contain a NUL", ErrInvalidInput)
	}

	password := security.Reveal(secret)
	if strings.ContainsRune(password, 0) {
		// A NUL inside the password would add a third separator and change which
		// bytes the broker reads as the password. Refusing is the only safe
		// answer: sending it would put a *different* credential on the wire than
		// the operator supplied.
		return Tune{}, fmt.Errorf("%w: a password may not contain a NUL", ErrInvalidInput)
	}

	// The SASL PLAIN response: 0x00 || username || 0x00 || password. Exactly two
	// NUL separators, no authorization identity, no trailing byte. This is the
	// encoder ADR 0068 section 8 requires a byte-exact test for, because an
	// off-by-one here writes the operator's password into the broker's log.
	response := make([]byte, 0, 2+len(username)+len(password))
	response = append(response, 0x00)
	response = append(response, username...)
	response = append(response, 0x00)
	response = append(response, password...)

	payload := clientProperties()
	payload, err := appendShortstr(payload, "PLAIN")
	if err != nil {
		return Tune{}, err
	}
	payload = appendLongstr(payload, response)
	payload, err = appendShortstr(payload, "en_US")
	if err != nil {
		return Tune{}, err
	}

	f, err := c.exchange(ctx, timeout, encodeMethod(mStartOk, payload))
	if err != nil {
		return Tune{}, err
	}

	switch {
	case f.classID == classConnection && f.methodID == inTune:
		cur := &cursor{b: f.fields}
		ch, err := cur.u16()
		if err != nil {
			return Tune{}, err
		}
		fm, err := cur.u32()
		if err != nil {
			return Tune{}, err
		}
		hb, err := cur.u16()
		if err != nil {
			return Tune{}, err
		}
		return Tune{ChannelMax: ch, FrameMax: fm, Heartbeat: hb}, nil

	case f.classID == classConnection && f.methodID == inSecure:
		// Not answered. Answering would be a second credential-bearing frame.
		return Tune{}, ErrSecureChallenge

	case f.classID == classConnection && f.methodID == inClose:
		refusal, perr := c.parseClose(f)
		if perr != nil {
			return Tune{}, perr
		}
		return Tune{}, &RefusedError{Refusal: refusal}

	default:
		return Tune{}, fmt.Errorf("%w: expected connection.tune, got %d/%d",
			ErrUnexpectedFrame, f.classID, f.methodID)
	}
}

// SelectTune computes the frozen Tune-Ok values from the peer's offer.
//
// # Zero is not "no limit" here
//
// RabbitMQ refuses a client value of 0 for either field whenever its own
// configured value is non-zero, which is the default. Phase 8.0C measured all
// three refusals — channel_max 0, frame_max 0 and an over-limit channel_max —
// and every one was a **silent close after about three seconds**, with no
// Connection.Close frame at all.
//
// # The values
//
//   - channel_max 1: RabbitMQ's own CHANNEL_MIN, and no larger than any non-zero
//     server value measured. svcdoctor opens zero channels, so 1 is the smallest
//     legal statement it can make.
//   - frame_max: 8192 clamped down to the server's offer. 8192 is RabbitMQ's
//     ?FRAME_MIN_SIZE on current releases; the clamp satisfies the 4096 floor of
//     3.13 and 4.0 and LavinMQ and the 8192 floor of 4.1+ at once.
//   - heartbeat 0: RabbitMQ honours the client's value verbatim, so advertising
//     a non-zero one would be a promise svcdoctor does not keep. Sending 0 makes
//     "does BASIC need a heartbeat loop" unreachable rather than unlikely.
func SelectTune(offer Tune) (Selected, error) {
	frameMax := uint32(postTuneFrameMax)
	if offer.FrameMax != 0 && offer.FrameMax < frameMax {
		frameMax = offer.FrameMax
	}
	if frameMax < specFrameMinSize {
		// Only reachable against a broker configured below the AMQP
		// frame-min-size floor, which no client can satisfy.
		return Selected{}, fmt.Errorf("%w: the endpoint offered frame_max %d, below the %d floor",
			ErrTuneUnsupported, offer.FrameMax, specFrameMinSize)
	}
	return Selected{ChannelMax: 1, FrameMax: frameMax, Heartbeat: 0}, nil
}

// SendTuneOk answers the negotiation. There is no reply to read.
func (c *Conn) SendTuneOk(ctx context.Context, timeout time.Duration, sel Selected) error {
	payload := make([]byte, 0, 8)
	payload = binary.BigEndian.AppendUint16(payload, sel.ChannelMax)
	payload = binary.BigEndian.AppendUint32(payload, sel.FrameMax)
	payload = binary.BigEndian.AppendUint16(payload, sel.Heartbeat)

	if err := c.send(ctx, timeout, encodeMethod(mTuneOk, payload)); err != nil {
		return err
	}
	// The parser may now accept what svcdoctor promised to accept, and nothing
	// wider: negotiated clamps to what this package advertises.
	c.rd.negotiated(sel.FrameMax - frameOverhead)
	return nil
}

// Open requests the virtual host and reads Connection.Open-Ok.
//
// Its success is the terminal boundary of RabbitMQ BASIC. No channel is opened
// afterwards, and no resource is named before or after.
func (c *Conn) Open(ctx context.Context, timeout time.Duration) error {
	if len(c.vhost) > MaxVHostBytes {
		return fmt.Errorf("%w: virtual host of %d bytes exceeds the %d byte protocol maximum",
			ErrInvalidInput, len(c.vhost), MaxVHostBytes)
	}

	payload, err := appendShortstr(nil, c.vhost)
	if err != nil {
		return err
	}
	payload, err = appendShortstr(payload, "") // reserved-1
	if err != nil {
		return err
	}
	payload = append(payload, 0x00) // reserved-2

	f, err := c.exchange(ctx, timeout, encodeMethod(mOpen, payload))
	if err != nil {
		return err
	}

	switch {
	case f.classID == classConnection && f.methodID == inOpenOk:
		return nil
	case f.classID == classConnection && f.methodID == inClose:
		refusal, perr := c.parseClose(f)
		if perr != nil {
			return perr
		}
		return &RefusedError{Refusal: refusal}
	default:
		return fmt.Errorf("%w: expected connection.open-ok, got %d/%d",
			ErrUnexpectedFrame, f.classID, f.methodID)
	}
}

// parseClose decodes a Connection.Close into a normalized Refusal.
//
// The reply text is read into a local, compared, and left to the garbage
// collector. It is not stored on Refusal, not returned and not wrapped.
func (c *Conn) parseClose(f frame) (Refusal, error) {
	cur := &cursor{b: f.fields}
	code, err := cur.u16()
	if err != nil {
		return Refusal{}, err
	}
	text, err := cur.shortstr()
	if err != nil {
		return Refusal{}, err
	}
	classID, err := cur.u16()
	if err != nil {
		return Refusal{}, err
	}
	methodID, err := cur.u16()
	if err != nil {
		return Refusal{}, err
	}

	return Refusal{
		ReplyCode:    code,
		Outcome:      normalizeClose(code, text, c.vhost, c.username),
		PeerClassID:  classID,
		PeerMethodID: methodID,
	}, nil
}

// AckClose answers a peer-initiated Connection.Close.
//
// It releases the broker's connection process immediately rather than after its
// timer, and it carries nothing.
func (c *Conn) AckClose(ctx context.Context, timeout time.Duration) error {
	return c.send(ctx, timeout, encodeMethod(mCloseOk, nil))
}

// GracefulClose ends a successful journey politely.
//
// # It cannot change a verdict
//
// Evidence is immutable and Open-Ok was recorded when it arrived (ADR 0003). A
// failure here is an attribute, not a finding, and the AMQP specification agrees:
// a peer that detects socket closure without Close-Ok *SHOULD log the error*.
//
// # It has a cost-side reason, not only a courtesy one
//
// Dropping the socket makes RabbitMQ log "client unexpectedly closed TCP
// connection" at warning level, and svcdoctor must not manufacture warnings in
// an operator's log.
func (c *Conn) GracefulClose(ctx context.Context, timeout time.Duration) error {
	payload := binary.BigEndian.AppendUint16(nil, 200)
	payload, err := appendShortstr(payload, "")
	if err != nil {
		return err
	}
	payload = binary.BigEndian.AppendUint16(payload, 0) // class-id
	payload = binary.BigEndian.AppendUint16(payload, 0) // method-id

	f, err := c.exchange(ctx, timeout, encodeMethod(mClose, payload))
	if err != nil {
		return err
	}
	if f.classID != classConnection || f.methodID != inCloseK {
		return fmt.Errorf("%w: expected connection.close-ok, got %d/%d",
			ErrUnexpectedFrame, f.classID, f.methodID)
	}
	return nil
}

// RefusedError carries a normalized refusal as an error value.
//
// It holds no peer text. Its message names the outcome constant, which this
// package declared.
type RefusedError struct {
	Refusal Refusal
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("%s: reply code %d, outcome %s",
		ErrRefused.Error(), e.Refusal.ReplyCode, e.Refusal.Outcome)
}

func (e *RefusedError) Unwrap() error { return ErrRefused }

// errorsIs is a tiny indirection so that the header-refusal check reads as one
// idea rather than two imports at the call site.
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target { //nolint:errorlint // identity check is the intent
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper) //nolint:errorlint // walking the chain manually
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
