package wire

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"net"

	"github.com/hakanaltindag/svcdoctor/internal/sasl/scram"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// MechanismSCRAMSHA256 is the only SASL mechanism svcdoctor performs for
// PostgreSQL.
//
// It is exported because the adapter must decide whether the server advertised
// it before deciding to authenticate at all, and that decision must compare
// against the same string this package sends. One constant, one meaning — and
// since Phase 6.2 that meaning comes from the shared core, so the name the
// mechanism check compares and the name the exchange performs cannot drift.
const MechanismSCRAMSHA256 = scram.MechanismSHA256

// MaxSCRAMIterations bounds the PBKDF2 work svcdoctor will perform for one
// exchange.
//
// The bound moved to internal/sasl/scram in Phase 6.2 and this is an alias, so
// nothing that referenced the constant had to change. The reasoning is
// unchanged and is recorded on scram.MaxIterations: the server names the
// iteration count, so it is the only value in the exchange that decides how much
// CPU a diagnostic tool spends, and 1048576 is 256 times PostgreSQL's default
// for about a quarter of a second of work.
//
// **The numeric ceiling is the core's, and mapping a refusal into evidence is
// this service's.** That split is ADR 0056 section 7: the CPU being protected is
// svcdoctor's and is service-independent, while EXEC_UNSUPPORTED_BY_SVCDOCTOR is
// a claim in PostgreSQL's evidence model.
const MaxSCRAMIterations = scram.MaxIterations

// SCRAM is what one SCRAM-SHA-256 exchange observed, in plain Go values.
//
// # What it deliberately does not carry
//
// There is no field for the password, the prepared password, either nonce, the
// salt, the salted password, the client key, the stored key, the client
// signature, the client proof, the server key, the server signature, the auth
// message, or the server's SCRAM error token. **Structural absence is the
// mechanism**: a caller cannot leak a value this package never returns, and no
// future edit to a caller can start leaking one without editing this struct
// first.
//
// The three fields below are safe protocol facts. Two are booleans about what
// happened, and the third is a server configuration value that carries no
// identity.
//
// There is deliberately **no field recording whether the client proof reached
// the socket.** One existed, so that the adapter could infer a credential
// rejection from an `08P01` arriving after it. That inference was unsound — see
// authSQLStateFailure in the adapter — and the field was removed with it rather
// than left available for the next caller to reach for.
type SCRAM struct {
	// Iterations is the PBKDF2 iteration count the server named, once a
	// server-first message parsed. Zero means none was read.
	Iterations int

	// Verified reports whether the server's signature matched the one derived
	// locally, which is the only thing that proves the peer knows the
	// credential.
	Verified bool

	// Complete reports whether AuthenticationOk arrived after a verified
	// signature. It is the second half of the success condition and never the
	// whole of it.
	Complete bool

	// Fields is what an ErrorResponse retained, when one ended the exchange. It
	// holds a SQLSTATE and the non-localized severity, and nothing else.
	Fields ErrorFields
}

// AuthenticateSCRAM runs one SCRAM-SHA-256 exchange over conn and stops at
// AuthenticationOk.
//
// The connection is borrowed and never closed; deadlines derived from ctx are
// cleared before returning. It must already have received an AuthenticationSASL
// message advertising SCRAM-SHA-256, which is what the caller's type and the
// caller's mechanism check guarantee.
//
// # This is where a secret becomes bytes
//
// It is the only function in the PostgreSQL adapter that calls security.Reveal,
// and one of exactly two in svcdoctor. The caller obtained the secret from
// Credential.SecretFor, so the endpoint binding was verified, and checked the
// channel policy and the mechanism before calling. **This function performs none
// of those checks**: duplicating them here would mean two places could disagree
// about whether a credential may be sent, and the wire boundary is the wrong one
// of the two to hold policy. See ADR 0027 for why the boundary is here and ADR
// 0038 for what the caller must have established before arriving.
//
// # What moved out in Phase 6.2, and what deliberately did not
//
// The RFC 5802 semantics — nonce generation, SASLname encoding, the server-first
// grammar, every bound, the derivation of the proof and the mandatory server
// signature check — live in internal/sasl/scram, shared with Kafka.
//
// **The plaintext did not move with them.** The shared core exposes no API that
// accepts a password; it receives the callback below, which closes over the
// revealed value and performs PBKDF2 here. What crosses the package boundary is
// a SaltedPassword: credential-derived and sensitive, but scoped to this
// principal on this server for this salt rather than being the operator's
// reusable credential. That is Model D, and ADR 0055 records why the simpler
// design — handing the core a password — was rejected.
//
// # Where it stops
//
// At AuthenticationOk, having read exactly that frame and no further. The
// ParameterStatus, BackendKeyData and ReadyForQuery a server sends in the same
// burst are left on the socket for the session step. Every read here is an
// exact-length read straight off the net.Conn — there is no bufio.Reader on this
// path, so no byte belonging to a later step can be taken into a buffer that
// step has no handle on.
func AuthenticateSCRAM(ctx context.Context, conn net.Conn, secret security.Secret) (SCRAM, error) {
	return authenticateSCRAM(ctx, conn, secret)
}

// authenticateSCRAM drives the exchange over one borrowed connection.
//
// # Order
//
// The password is revealed and immediately checked. Nothing between those two
// statements can start an exchange, derive a key, or write a byte, because there
// is nothing between them. See ADR 0038 section 11.1.1 for why the check cannot
// precede the reveal: security.Secret exposes no way to learn anything about its
// content, by construction, and deciding whether a password is printable ASCII
// *is* an inspection of the plaintext.
//
// # Lifetime
//
// The plaintext exists as a local here and inside the closure passed to
// Continue, which the shared core invokes exactly once and never retains. It is
// not stored, not logged, not returned, and not placed in any error. **No
// erasure is claimed and none is performed**: crypto/pbkdf2 copies the string,
// the derived slices are copied into the frames written to the socket, and Go
// strings are immutable and may already have been moved by the collector.
// Zeroing anything here would leave live copies untouched while implying the
// value was gone. internal/security/doc.go has stated since Phase 1 that Go
// cannot guarantee erasure; a Zero call would be theatre that contradicts it.
func authenticateSCRAM(ctx context.Context, conn net.Conn, secret security.Secret) (SCRAM, error) {
	if conn == nil {
		return SCRAM{}, ErrInvalidInput
	}

	password := security.Reveal(secret)
	if !printableASCII(password) {
		// Refused before a deadline is bound, before an exchange exists, before
		// any derivation, and before a byte is written.
		return SCRAM{}, ErrPasswordUnsupported
	}

	release := bindDeadline(ctx, conn)
	defer release()

	// The username is empty and that is the correct PostgreSQL form: the role
	// travelled in the StartupMessage and the server ignores this attribute
	// entirely — verified against a real server with a deliberately wrong value,
	// which still authenticated. Sending it would add a second place a role name
	// must be SCRAM-escaped for no protocol effect.
	//
	// RFC 5802's saslname production is 1*(...), so an empty username is not
	// strictly grammatical; PostgreSQL requires it anyway, and the shared core
	// permits it deliberately for exactly this caller. Kafka, which reads its
	// principal from this field, refuses an empty one before it gets here.
	exchange, clientFirstBare, err := scram.Begin("")
	if err != nil {
		return SCRAM{}, translateSCRAM(err)
	}

	initial, err := saslInitialResponse(scram.GS2Header + clientFirstBare)
	if err != nil {
		return SCRAM{}, err
	}
	if err := writeAll(conn, initial); err != nil {
		return SCRAM{}, err
	}

	serverFirstRaw, fields, err := readSASLPayload(conn, authCodeSASLContinue)
	if err != nil {
		return SCRAM{Fields: fields}, err
	}

	// iterations is captured rather than returned, because the shared core
	// hands the count to the derivation and returns only the client-final
	// message. It is recorded for evidence: ADR 0038 section 18 classifies the
	// iteration count as a safe protocol fact, and it is the only value from
	// this exchange that may leave the package.
	var iterations int
	clientFinal, err := exchange.Continue(serverFirstRaw, func(salt []byte, count int) ([]byte, error) {
		iterations = count
		// **The only thing this closure captures is the revealed password.** Not
		// the connection, not the context, not the secret, not the deadline —
		// capturing any of those would hand the shared core authority it is
		// designed not to have, and TestDerivationClosureCapturesOnlyThePassword
		// fails if one appears here. See ADR 0056 section 11.
		return pbkdf2.Key(sha256.New, password, salt, count, sha256.Size)
	})
	out := SCRAM{Iterations: iterations}
	if err != nil {
		return out, translateSCRAM(err)
	}

	final, err := saslResponse(clientFinal)
	if err != nil {
		return out, err
	}
	if err := writeAll(conn, final); err != nil {
		return out, err
	}

	serverFinalRaw, fields, err := readSASLPayload(conn, authCodeSASLFinal)
	if err != nil {
		out.Fields = fields
		return out, err
	}

	if err := exchange.Verify(serverFinalRaw); err != nil {
		return out, translateSCRAM(err)
	}
	out.Verified = true

	// Only now may AuthenticationOk mean anything. A peer that sent it earlier
	// was refused above, because a client that accepts it without a verified
	// signature has proved itself to the peer and learned nothing about the peer.
	if err := readAuthenticationOk(conn, &out); err != nil {
		return out, err
	}
	out.Complete = true
	return out, nil
}

// printableASCII reports whether every code point of s is in U+0020..U+007E.
//
// The loop is over bytes and that is exactly equivalent here, with no decoding
// step: every code point at or above U+0080 encodes in UTF-8 as bytes in
// 0x80..0xBF or 0xC2..0xF4, and none of those falls in 0x20..0x7E. Invalid UTF-8
// is refused by the same test, which is the right answer — the guarantee being
// relied on is that SASLprep is the identity function over this range, and an
// undecodable byte sequence is not in it.
//
// # Why this stays here rather than moving with the rest
//
// It inspects the **plaintext password**, and plaintext does not cross into
// internal/sasl/scram. That package holds an identical predicate for the
// username, which is not a secret; this one holds it for the password, which is.
// The duplication is the design: a shared helper would need the password as an
// argument, which is the one thing Model D exists to prevent (ADR 0055).
//
// # Why the restriction exists at all
//
// PostgreSQL applies SASLprep (RFC 4013) to a password on both sides: when
// `CREATE ROLE ... PASSWORD` builds the verifier, and in libpq before deriving.
// A client that skips it computes a different key and the server answers
// `28P01` — a *correct* password reported as rejected. Measured on PostgreSQL
// 14.24 and 18.6 with passwords containing U+00A0 and U+00AD.
//
// Over printable ASCII, SASLprep provably changes nothing: no mapping-table
// member is ASCII, NFKC is the identity because no ASCII code point decomposes
// and no ASCII pair composes, and the prohibited ASCII set is U+0000..U+001F
// with U+007F. Outside that range svcdoctor refuses rather than guessing, which
// is a truthful "svcdoctor cannot do this" instead of a false claim about the
// target. See ADR 0038 section 11.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Authentication message codes this exchange reads.
const (
	authCodeOK            uint32 = 0
	authCodeSASLContinue  uint32 = 11
	authCodeSASLFinal     uint32 = 12
	authRequestCodeLength        = 4
)

// readSASLPayload reads one message and requires it to be the expected
// Authentication step, returning its SASL payload.
//
// A NoticeResponse is skipped, because the protocol permits one almost anywhere
// and it answers nothing. An ErrorResponse ends the exchange and its retained
// fields come back so the caller can classify by SQLSTATE. Anything else —
// including an AuthenticationOk arriving where a SASL step belongs — is a
// protocol violation at this point and is refused rather than accommodated.
func readSASLPayload(conn net.Conn, want uint32) (string, ErrorFields, error) {
	msg, fields, err := readAuthStep(conn)
	if err != nil {
		return "", fields, err
	}

	code, payload, err := authCodeAndPayload(msg.Body)
	if err != nil {
		return "", ErrorFields{}, err
	}
	if code != want {
		return "", ErrorFields{}, ErrUnexpectedResponse
	}
	return string(payload), ErrorFields{}, nil
}

// readAuthenticationOk requires the next message to be AuthenticationOk.
//
// It reads exactly that frame. Whatever the server sent in the same burst —
// ParameterStatus, BackendKeyData, ReadyForQuery — stays on the socket for the
// session step, which is the boundary ADR 0036 section 5 fixed.
func readAuthenticationOk(conn net.Conn, out *SCRAM) error {
	msg, fields, err := readAuthStep(conn)
	if err != nil {
		out.Fields = fields
		return err
	}

	code, payload, err := authCodeAndPayload(msg.Body)
	if err != nil {
		return err
	}
	if code != authCodeOK || len(payload) != 0 {
		return ErrUnexpectedResponse
	}
	return nil
}

// readAuthStep reads until the peer says something decisive.
func readAuthStep(conn net.Conn) (Message, ErrorFields, error) {
	// A bound on notices, so a peer cannot hold the exchange open forever by
	// sending them. The caller's context bounds total time regardless; this
	// bounds the message count independently of how fast they arrive.
	const maxNotices = 32

	for i := 0; i <= maxNotices; i++ {
		msg, err := readMessage(conn)
		if err != nil {
			return Message{}, ErrorFields{}, err
		}

		switch msg.Type {
		case MsgNoticeResponse:
			continue
		case MsgAuthentication:
			return msg, ErrorFields{}, nil
		case MsgErrorResponse:
			fields, decodeErr := DecodeErrorFields(msg.Body)
			if decodeErr != nil {
				return Message{}, ErrorFields{}, decodeErr
			}
			return Message{}, fields, ErrUnexpectedResponse
		default:
			return Message{}, ErrorFields{}, ErrUnexpectedResponse
		}
	}
	return Message{}, ErrorFields{}, ErrUnexpectedResponse
}

// authCodeAndPayload splits an Authentication body into its code and the
// method-specific data after it.
//
// The payload is read here rather than through DecodeAuthRequest on purpose:
// AuthRequest deliberately carries no challenge data, and adding a field for it
// would let SCRAM material travel upward out of this package on a type the
// startup step also returns. Keeping the split local means the salt, the nonces
// and the server signature exist only inside this file.
func authCodeAndPayload(body []byte) (uint32, []byte, error) {
	if len(body) < authRequestCodeLength {
		return 0, nil, ErrMalformedMessage
	}
	return binary.BigEndian.Uint32(body[:authRequestCodeLength]), body[authRequestCodeLength:], nil
}

// saslInitialResponse frames the first client message.
//
// Body: the mechanism name NUL-terminated, a 32-bit length, then the payload.
// The mechanism is always MechanismSCRAMSHA256 — this package performs exactly
// one, and a parameter would imply a choice it cannot make.
func saslInitialResponse(payload string) ([]byte, error) {
	if len(payload) > MaxMessageSize {
		return nil, ErrInvalidInput
	}
	body := make([]byte, 0, len(MechanismSCRAMSHA256)+1+4+len(payload))
	body = append(body, MechanismSCRAMSHA256...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint32(body, boundedLength(len(payload)))
	body = append(body, payload...)
	return encodeMessage(msgSASLResponse, body)
}

// saslResponse frames a continuation client message, which is the bare payload.
func saslResponse(payload string) ([]byte, error) {
	return encodeMessage(msgSASLResponse, []byte(payload))
}

// boundedLength narrows a length that callers have already bounded by
// MaxMessageSize.
//
// The bound is re-asserted here rather than assumed, because the conversion is
// the one place a length becomes unrecoverable: a value that somehow arrived
// out of range would otherwise be truncated into a frame header that disagrees
// with the body, which is the class of bug that turns into a parser confusion.
// Clamping is safe rather than silent — every caller checks first, so the clamp
// is unreachable, and it exists so that no path can produce a wrapped length.
func boundedLength(n int) uint32 {
	if n < 0 || n > MaxMessageSize+frameHeaderOverhead {
		return MaxMessageSize + frameHeaderOverhead
	}
	return uint32(n)
}

// frameHeaderOverhead is the four length bytes a frame counts in its own length.
const frameHeaderOverhead = 4

// msgSASLResponse is 'p', the type byte both client SASL messages use.
const msgSASLResponse byte = 'p'

// encodeMessage builds a standard typed message: a type byte, a 32-bit length
// that includes itself, then the body.
//
// The body is bounded by MaxMessageSize, which is the same bound readMessage
// enforces on the way in. That symmetry is the point: **svcdoctor never writes a
// frame it would refuse to read.** Everything this file encodes is a nonce and a
// base64 proof and is orders of magnitude below the bound, so the check is an
// invariant rather than a limit anybody will meet — and it is what makes the
// length conversion below provably safe instead of merely obviously safe.
//
// The test fixtures deliberately keep their own framing helper rather than
// calling this one. A fixture that built its bytes with the encoder under test
// would agree with it about a framing bug.
func encodeMessage(kind byte, body []byte) ([]byte, error) {
	if len(body) > MaxMessageSize {
		return nil, ErrInvalidInput
	}
	out := make([]byte, 5+len(body))
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:5], boundedLength(4+len(body)))
	copy(out[5:], body)
	return out, nil
}
