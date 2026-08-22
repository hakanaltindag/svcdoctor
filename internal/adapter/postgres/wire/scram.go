package wire

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// MechanismSCRAMSHA256 is the only SASL mechanism svcdoctor performs.
//
// It is exported because the adapter must decide whether the server advertised
// it before deciding to authenticate at all, and that decision must compare
// against the same string this package sends. One constant, one meaning.
const MechanismSCRAMSHA256 = "SCRAM-SHA-256"

// MaxSCRAMIterations bounds the PBKDF2 work svcdoctor will perform for one
// exchange.
//
// The server names the iteration count, so it is the only value in this exchange
// that decides how much CPU a diagnostic tool spends. PostgreSQL's
// `scram_iterations` is settable per session by any role, with `max_val`
// 2147483647; libpq validates only `>= 1` and imposes no ceiling at all. A peer
// answering with the maximum buys roughly eight minutes of PBKDF2 for four bytes
// of ASCII, measured.
//
// 1048576 is 256 times PostgreSQL's default of 4096, sixteen times the highest
// value observed in a real configuration, and about a quarter of a second of
// work. A count above it is refused **before any derivation runs**. See ADR 0038
// section 16.
const MaxSCRAMIterations = 1 << 20

// gs2Header is the GS2 header svcdoctor sends, and it is not negotiable.
//
// RFC 5802 section 5 defines "n" as *"client doesn't support channel binding"*,
// which is the truthful statement for this implementation, and PostgreSQL
// accepts it unconditionally — including over TLS with SCRAM-SHA-256-PLUS first
// in the advertised list.
//
// "y" is **never** sent. It means "I support channel binding but I think you do
// not", which is a downgrade claim, and a real PostgreSQL server refuses it with
// `28000` when it does offer -PLUS. The authorization identity is absent rather
// than empty-and-present, because PostgreSQL rejects any authzid outright with
// `0A000`. See ADR 0038 section 4.
const gs2Header = "n,,"

// scramRawNonceLen is the client nonce length in bytes before encoding.
//
// Eighteen matches libpq's SCRAM_RAW_NONCE_LEN, which matters twice: it is the
// shape every PostgreSQL-compatible server has been tested against, and it is
// divisible by three, so the base64 encoding is 24 characters with no "="
// padding to worry about against the RFC's printable-character rule.
const scramRawNonceLen = 18

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

// nonceSource produces one base64-encoded client nonce.
//
// It is an unexported function type rather than an exported interface on
// purpose. Deterministic nonces are needed to pin exact message bytes in a test,
// and that is the entire requirement; a public randomness abstraction would be a
// seam anybody could reach and a production caller could set.
type nonceSource func() (string, error)

// cryptoNonce is the production source: 18 bytes of crypto/rand, base64-encoded.
func cryptoNonce() (string, error) {
	var raw [scramRawNonceLen]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
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
// # Where it stops
//
// At AuthenticationOk, having read exactly that frame and no further. The
// ParameterStatus, BackendKeyData and ReadyForQuery a server sends in the same
// burst are left on the socket for the session step. Every read here is an
// exact-length read straight off the net.Conn — there is no bufio.Reader on this
// path, so no byte belonging to a later step can be taken into a buffer that
// step has no handle on.
func AuthenticateSCRAM(ctx context.Context, conn net.Conn, secret security.Secret) (SCRAM, error) {
	return authenticateSCRAM(ctx, conn, secret, cryptoNonce)
}

// authenticateSCRAM is the deterministic-nonce core.
//
// # Order
//
// The password is revealed and immediately checked. Nothing between those two
// statements can generate a nonce, derive a key, or write a byte, because there
// is nothing between them. See ADR 0038 section 11.1.1 for why the check cannot
// precede the reveal: security.Secret exposes no way to learn anything about its
// content, by construction, and deciding whether a password is printable ASCII
// *is* an inspection of the plaintext.
//
// # Lifetime
//
// The plaintext exists as a local here and inside the PBKDF2 call. It is not
// stored, not logged, not returned, and not placed in any error. **No erasure is
// claimed and none is performed**: crypto/pbkdf2 copies the string, the derived
// slices are copied into the frames written to the socket, and Go strings are
// immutable and may already have been moved by the collector. Zeroing anything
// here would leave live copies untouched while implying the value was gone.
// internal/security/doc.go has stated since Phase 1 that Go cannot guarantee
// erasure; a Zero call would be theatre that contradicts it.
func authenticateSCRAM(
	ctx context.Context, conn net.Conn, secret security.Secret, nonces nonceSource,
) (SCRAM, error) {
	if conn == nil {
		return SCRAM{}, ErrInvalidInput
	}

	password := security.Reveal(secret)
	if !printableASCII(password) {
		// Refused before a deadline is bound, before a nonce exists, before any
		// derivation, and before a byte is written.
		return SCRAM{}, ErrPasswordUnsupported
	}

	release := bindDeadline(ctx, conn)
	defer release()

	clientNonce, err := nonces()
	if err != nil {
		return SCRAM{}, err
	}

	// client-first-bare. The username field is empty and that is the correct
	// PostgreSQL form: the role travelled in the StartupMessage and the server
	// ignores this attribute entirely — verified against a real server with a
	// deliberately wrong value, which still authenticated. Sending it would add
	// a second place a role name must be SCRAM-escaped for no protocol effect.
	clientFirstBare := "n=,r=" + clientNonce

	initial, err := saslInitialResponse(gs2Header + clientFirstBare)
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

	first, err := parseServerFirst(serverFirstRaw, clientNonce)
	if err != nil {
		return SCRAM{}, err
	}
	// Everything the peer chose has now been validated. The iteration ceiling in
	// particular was applied inside the parse, so no PBKDF2 has run.
	out := SCRAM{Iterations: first.iterations}

	proof, expectedSignature, err := derive(password, clientFirstBare, serverFirstRaw, first)
	if err != nil {
		return out, err
	}

	final, err := saslResponse(proof)
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

	if err := verifyServerFinal(serverFinalRaw, expectedSignature); err != nil {
		return out, err
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
// # Why this restriction exists at all
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

// serverFirst is a validated server-first message.
type serverFirst struct {
	nonce      string
	salt       []byte
	iterations int
}

// parseServerFirst validates everything the peer chose, and derives nothing.
//
// It parses structurally into comma-separated single-letter attributes; there is
// no substring search anywhere, because a peer that can place "i=" inside a salt
// should not be able to steer a heuristic.
//
// Every rule below is a refusal to continue rather than a warning:
//
//   - r, s and i are all required, and each may appear exactly once.
//   - The server nonce must **strictly extend** the client nonce: the prefix must
//     match and the result must be longer. RFC 5802 section 5 requires the prefix
//     check; the length check is separate because a nonce equal to the client's
//     adds no server entropy and defeats the replay protection the nonce exists
//     for.
//   - The salt must be valid standard base64.
//   - The iteration count must be a positive decimal integer within
//     MaxSCRAMIterations.
//   - A mandatory extension ("m") must be refused, as RFC 5802 section 7
//     requires of a client that does not understand it.
//
// Unrecognized non-mandatory attributes are ignored, which is what the RFC's
// extension rule asks for.
func parseServerFirst(raw, clientNonce string) (serverFirst, error) {
	var (
		out                      serverFirst
		haveR, haveS, haveI      bool
		nonce, saltText, iterStr string
	)

	err := scramAttributes(raw, func(key byte, value string) error {
		switch key {
		case 'r':
			if haveR {
				return ErrMalformedMessage
			}
			haveR, nonce = true, value
		case 's':
			if haveS {
				return ErrMalformedMessage
			}
			haveS, saltText = true, value
		case 'i':
			if haveI {
				return ErrMalformedMessage
			}
			haveI, iterStr = true, value
		case 'm':
			// A mandatory extension this implementation does not understand.
			// RFC 5802 section 7 requires failing rather than proceeding.
			return ErrUnexpectedResponse
		default:
			// A non-mandatory extension. Ignored by design.
		}
		return nil
	})
	if err != nil {
		return serverFirst{}, err
	}

	if !haveR || !haveS || !haveI {
		return serverFirst{}, ErrMalformedMessage
	}
	// Strictly extending: the prefix must be svcdoctor's own nonce, and the
	// result must be longer. Compared as an exact slice equality against a value
	// this process generated, never as a search through peer-chosen text.
	if len(nonce) <= len(clientNonce) || nonce[:len(clientNonce)] != clientNonce {
		return serverFirst{}, ErrMalformedMessage
	}

	salt, err := base64.StdEncoding.DecodeString(saltText)
	if err != nil {
		return serverFirst{}, ErrMalformedMessage
	}

	iterations, err := parseIterations(iterStr)
	if err != nil {
		return serverFirst{}, err
	}

	out.nonce, out.salt, out.iterations = nonce, salt, iterations
	return out, nil
}

// scramAttributes walks the comma-separated `k=v` attributes of a SCRAM message.
//
// # Why this is hand-written rather than a strings.Split
//
// TestNoEnglishMessageClassification forbids the strings search and split
// functions in every production file that interprets a peer's reply, because a
// classifier that reads prose makes confident claims about bytes the peer chose.
// **This file takes no exemption from that rule.** The scan below is a
// byte-level grammar walk — a comma delimiter, an `=` separator and single-letter
// keys, all fixed by RFC 5802 — and writing it out means a reader can see that
// scram.go performs no text operation at all, rather than having to trust an
// exemption entry.
//
// An attribute shorter than two bytes, or whose second byte is not `=`, is
// malformed: the sender announced a grammar it did not follow.
func scramAttributes(raw string, visit func(key byte, value string) error) error {
	for {
		end := len(raw)
		for i := 0; i < len(raw); i++ {
			if raw[i] == ',' {
				end = i
				break
			}
		}

		attr := raw[:end]
		if len(attr) < 2 || attr[1] != '=' {
			return ErrMalformedMessage
		}
		if err := visit(attr[0], attr[2:]); err != nil {
			return err
		}

		if end == len(raw) {
			return nil
		}
		raw = raw[end+1:]
	}
}

// parseIterations reads the iteration count and applies svcdoctor's ceiling.
//
// The digit scan happens first so that the two failures stay distinguishable: a
// value that is not a number is a malformed message and says something about the
// peer's framing, while a number too large for svcdoctor is a gap in svcdoctor
// and says nothing about the peer at all. A value that overflows is in the
// second category, because it is unambiguously above the ceiling.
//
// A count *below* RFC 7677's recommended 4096 is accepted. The RFC says SHOULD,
// PostgreSQL's own minimum is 1, and a server configured that low is a real
// deployment with a real weakness — refusing would make svcdoctor blind exactly
// where its report would be most useful. The count is recorded, so a rule can
// say so later.
func parseIterations(v string) (int, error) {
	if v == "" {
		return 0, ErrMalformedMessage
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, ErrMalformedMessage
		}
	}

	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		// Only a range error is reachable: every byte is a digit. A count that
		// does not fit in a uint64 is far above the ceiling.
		return 0, ErrIterationsUnsupported
	}
	if n == 0 {
		return 0, ErrMalformedMessage
	}
	if n > MaxSCRAMIterations {
		return 0, ErrIterationsUnsupported
	}
	return int(n), nil
}

// derive computes the client proof and the signature the server must produce.
//
// Straight RFC 5802 section 3 with SHA-256, from the standard library only. The
// channel-binding value is computed from the header actually sent rather than
// written as the constant "biws", so it cannot silently stop matching if the
// header ever changes — and the server includes that header in the value it
// verifies.
//
// **Nothing computed here leaves this function except the two values returned**,
// and neither of those leaves the exchange: the proof goes onto the socket and
// the expected signature is compared and discarded.
func derive(
	password, clientFirstBare, serverFirstRaw string, first serverFirst,
) (clientFinal string, expectedServerSignature []byte, err error) {
	saltedPassword, err := pbkdf2.Key(sha256.New, password, first.salt, first.iterations, sha256.Size)
	if err != nil {
		return "", nil, err
	}

	clientKey := mac(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	channelBinding := base64.StdEncoding.EncodeToString([]byte(gs2Header))
	withoutProof := "c=" + channelBinding + ",r=" + first.nonce
	authMessage := clientFirstBare + "," + serverFirstRaw + "," + withoutProof

	clientSignature := mac(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}

	serverKey := mac(saltedPassword, []byte("Server Key"))
	expected := mac(serverKey, []byte(authMessage))

	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), expected, nil
}

// mac is HMAC-SHA-256.
func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// verifyServerFinal checks that the peer proved knowledge of the credential.
//
// **This is mandatory and it is the half of the exchange that authenticates the
// server.** RFC 5802 section 5: *"If the two are different, the client MUST
// consider the authentication exchange to be unsuccessful."* A peer that sends
// AuthenticationOk without getting here has proved nothing, and svcdoctor treats
// it as a failure however confident the message that follows sounds.
//
// # The error attribute is read and never kept
//
// RFC 5802 defines server-error-value as a token list *with* an extension
// production, so the token is not guaranteed to come from the closed set and a
// peer may put arbitrary text there. It is compared against exact tokens to
// choose a sentinel and then dropped: it reaches no field, no error and no
// evidence. No PostgreSQL or pgBouncer version observed sends one at all — both
// report SCRAM failures as an ErrorResponse — so this path is defensive.
//
// # Two outcomes, two directions
//
// A `v=` that does not match yields ErrServerSignatureMismatch, and that is
// **svcdoctor refusing the peer**, not the peer refusing svcdoctor. It is only
// reachable once the peer has accepted the client proof — a peer that rejects
// the proof never sends a `v=` at all — so the two must not be normalized
// together downstream. See ADR 0040 section 5.1.
func verifyServerFinal(raw string, expected []byte) error {
	// Only the first attribute decides the outcome; RFC 5802 permits trailing
	// extensions after it, which are ignored.
	end := len(raw)
	for i := 0; i < len(raw); i++ {
		if raw[i] == ',' {
			end = i
			break
		}
	}
	attr := raw[:end]
	if len(attr) < 2 || attr[1] != '=' {
		return ErrMalformedMessage
	}

	switch attr[0] {
	case 'e':
		switch attr[2:] {
		case "invalid-proof", "unknown-user":
			// Both are the peer refusing what it was presented: the proof did
			// not verify, or there is no such principal to verify it against.
			// Neither is read for its cause — the two are one outcome here, as
			// they are for 28P01.
			return ErrSCRAMRejected
		case "invalid-username-encoding":
			// **Not a credential refusal.** RFC 5802 defines this as the
			// username field failing SASLprep or `=`-escaping, which is a fault
			// in the value's encoding rather than a decision about the material.
			// Calling it a rejection would let a decoding fault reach diagnosis
			// as "the peer refused your credential".
			//
			// It is defensive and unobserved: this client sends `n=`, an empty
			// username, because the role travels in the StartupMessage — so
			// there is nothing here for a peer to fail to decode. Handled
			// anyway, at the conservative class, because a peer chooses this
			// token and svcdoctor does not get to assume it will not send one.
			return ErrUnexpectedResponse
		default:
			return ErrUnexpectedResponse
		}
	case 'v':
		signature, err := base64.StdEncoding.DecodeString(attr[2:])
		if err != nil {
			return ErrMalformedMessage
		}
		if !hmac.Equal(signature, expected) {
			return ErrServerSignatureMismatch
		}
		return nil
	default:
		return ErrMalformedMessage
	}
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
