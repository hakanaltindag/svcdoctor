package wire

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"net"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/sasl/scram"
)

// MechanismSCRAMSHA256 is the second SASL mechanism svcdoctor can perform for
// Kafka.
//
// It aliases the shared core's constant, so the name the adapter's mechanism
// guard compares against and the name this exchange performs are one value. The
// same arrangement as internal/adapter/postgres/wire, for the same reason.
//
// SCRAM-SHA-512 is deliberately absent. The core derives with SHA-256 and
// requires a 32-byte key; SHA-512 needs a decision about how the hash is pinned
// across the derivation callback, recorded as a reopen condition in ADR 0056
// rather than added because the abstraction would allow it.
const MechanismSCRAMSHA256 = scram.MechanismSHA256

// ErrSCRAMUsernameUnsupported means the identity is outside the range svcdoctor
// can prepare for SCRAM.
//
// A statement about svcdoctor and never about the broker: nothing was sent, so
// the peer expressed no opinion. It covers a non-printable-ASCII identity and an
// empty one, and the two are one outcome here because neither can produce a
// message and both are the run's input rather than the target's behaviour.
//
// **Empty is refused here rather than in the shared core**, because the core
// must accept an empty username: PostgreSQL sends one deliberately, carrying the
// role in its StartupMessage instead. Kafka has no startup message and the
// broker reads the principal from the SCRAM `n=` field, so an empty identity
// would authenticate as nobody. ADR 0056 section 5 places the decision with the
// caller for exactly this reason.
var ErrSCRAMUsernameUnsupported = errNew("kafka identity is outside the range svcdoctor can prepare for SCRAM")

// ErrSCRAMPasswordUnsupported means the password is outside the range svcdoctor
// can prepare for SCRAM.
//
// Kept distinct from ErrSCRAMUsernameUnsupported because the two name different
// inputs, and an operator fixing one should not be pointed at the other. Both
// classify identically — a gap in svcdoctor, never a target defect — so the
// distinction costs nothing downstream.
var ErrSCRAMPasswordUnsupported = errNew("password is outside the range svcdoctor can prepare for SCRAM")

// ErrSCRAMLocalDerivation means svcdoctor's own SCRAM derivation did not produce
// usable key material, or the exchange was driven out of order.
//
// Every cause is a defect in svcdoctor rather than anything the broker did.
// None is reachable from this package's call path — the callback is a literal,
// the exchange runs linearly, and PBKDF2 is asked for exactly sha256.Size bytes
// — and it exists so that if one ever becomes reachable it arrives as a
// capability gap instead of as an accusation against the cluster.
var ErrSCRAMLocalDerivation = errNew("svcdoctor could not complete its own SCRAM derivation")

// ErrSCRAMRejected means the broker refused the credential inside the SCRAM
// exchange, by answering the client proof with `e=invalid-proof` or
// `e=unknown-user` instead of a verifier.
//
// It aliases the shared core's sentinel. A broker that instead reports the
// refusal as a SaslAuthenticate error code produces no error here at all — the
// code is a normalized fact on SASLAuthenticate and the caller classifies it.
var ErrSCRAMRejected = scram.ErrRejected

// ErrSCRAMServerSignatureMismatch means the broker's signature did not match the
// one derived locally.
//
// **This is svcdoctor refusing the peer**, not the peer refusing svcdoctor, and
// it is only reachable once the broker has accepted the client proof — a broker
// that rejects the proof never sends a verifier at all. The two directions must
// not be normalized together downstream.
var ErrSCRAMServerSignatureMismatch = scram.ErrServerSignatureMismatch

// ErrSCRAMIterationsUnsupported means the broker demanded more PBKDF2 work than
// svcdoctor performs. The count is legal protocol and no derivation ran.
var ErrSCRAMIterationsUnsupported = scram.ErrIterationsUnsupported

// exchangeSCRAMSHA256 authenticates over conn with SASL/SCRAM-SHA-256.
//
// The connection is borrowed, not owned; see exchange. It must already have
// completed a SaslHandshake naming SCRAM-SHA-256, which is what the caller's
// type and the caller's mechanism guard guarantee.
//
// It is unexported and takes the plaintext rather than a security.Secret,
// because Authenticate is this package's single reveal boundary.
//
// # The shared core never sees the credential
//
// internal/sasl/scram owns the RFC 5802 semantics — the nonce, the SASLname
// encoding, the server-first grammar, every bound, the proof and the mandatory
// server-signature check — and it exposes no API that accepts a password. It
// receives the callback below, which closes over the revealed value and performs
// PBKDF2 **here**. What crosses the package boundary is a SaltedPassword:
// credential-derived and sensitive, but scoped to this principal on this broker
// for this salt rather than being the operator's reusable credential. That is
// Model D; ADR 0055 records why handing the core a password was rejected.
//
// # Two round trips, one connection, no fallback
//
// SaslHandshake v1 means authentication continues as SaslAuthenticate requests,
// so the SCRAM exchange is two of them: client-first out, server-first back,
// client-final out, server-final back. Both reuse correlationSASLAuthenticate,
// which is correct because the framing is strictly lock-step — each response is
// read to completion before the next request is written — and it is a decision
// rather than an accident (ADR 0056 section 14).
//
// A failure at any step is reported as what it was. Nothing here retries,
// downgrades to PLAIN, or tries a second mechanism.
func exchangeSCRAMSHA256(
	ctx context.Context, conn net.Conn, identity, password string,
) (SASLAuthenticate, error) {
	// Refused before an exchange exists, before a nonce is drawn, before any
	// derivation and before a byte is written. An empty identity would
	// authenticate as nobody; a non-ASCII one cannot be prepared, because
	// svcdoctor implements only the range over which SASLprep provably changes
	// nothing and Kafka does not apply SASLprep at all (KAFKA-6272).
	if identity == "" || !printableASCII(identity) {
		return SASLAuthenticate{}, ErrSCRAMUsernameUnsupported
	}

	if !printableASCII(password) {
		return SASLAuthenticate{}, ErrSCRAMPasswordUnsupported
	}

	exchangeState, clientFirstBare, err := scram.Begin(scram.Username(identity))
	if err != nil {
		return SASLAuthenticate{}, translateSCRAM(err)
	}

	first, err := exchangeSASLToken(ctx, conn, []byte(scram.GS2Header+clientFirstBare))
	if err != nil || first.ErrorCode != 0 {
		return normalizeSASLAuthenticate(first.response), err
	}

	clientFinal, err := exchangeState.Continue(string(first.token), func(salt []byte, count int) ([]byte, error) {
		// **The only thing this closure captures is the revealed password.** Not
		// the connection, not the context, not the secret — capturing any of
		// those would hand the shared core authority it is designed not to have.
		// TestKafkaDerivationClosureCapturesOnlyThePassword fails if one appears.
		return pbkdf2.Key(sha256.New, password, salt, count, sha256.Size)
	})
	if err != nil {
		return SASLAuthenticate{}, translateSCRAM(err)
	}

	final, err := exchangeSASLToken(ctx, conn, []byte(clientFinal))
	if err != nil || final.ErrorCode != 0 {
		return normalizeSASLAuthenticate(final.response), err
	}

	// Mandatory. A broker that reports success without a verifier this
	// credential derives has proved nothing, and svcdoctor treats it as a
	// failure however confident the error code sounds.
	if err := exchangeState.Verify(string(final.token)); err != nil {
		return normalizeSASLAuthenticate(final.response), translateSCRAM(err)
	}
	return normalizeSASLAuthenticate(final.response), nil
}

// saslToken is one SaslAuthenticate round trip's result.
//
// The broker's SASLAuthBytes stay inside this package: token is consumed by the
// shared core and never travels upward. Only the normalized SASLAuthenticate
// leaves, and it has no field the token could occupy.
type saslToken struct {
	response  *kmsg.SASLAuthenticateResponse
	token     []byte
	ErrorCode int16
}

// exchangeSASLToken sends one SASL token and reads the broker's answer.
func exchangeSASLToken(ctx context.Context, conn net.Conn, payload []byte) (saslToken, error) {
	request := kmsg.NewPtrSASLAuthenticateRequest()
	request.SetVersion(saslAuthenticateRequestVersion)
	request.SASLAuthBytes = payload

	response := kmsg.NewPtrSASLAuthenticateResponse()
	response.SetVersion(saslAuthenticateRequestVersion)

	if err := exchange(ctx, conn, correlationSASLAuthenticate, request, response); err != nil {
		return saslToken{response: response}, err
	}
	return saslToken{
		response:  response,
		token:     response.SASLAuthBytes,
		ErrorCode: response.ErrorCode,
	}, nil
}

// translateSCRAM maps a shared-core error into this package's vocabulary.
//
// The aliased sentinels pass through as themselves. The core's framing errors
// become this package's own, so a caller classifying a Kafka exchange keeps
// seeing Kafka errors. The local faults collapse into ErrSCRAMLocalDerivation.
//
// Nothing here wraps: every returned value is a package-level sentinel with
// fixed text, so no byte the broker chose can travel out through an error. That
// matters more for Kafka than for PostgreSQL, because a broker's SASL error
// message routinely names principals, listeners, realms and internal hosts —
// which is why ErrorMessage is dropped at this boundary too (ADR 0030).
func translateSCRAM(err error) error {
	switch {
	case err == nil:
		return nil
	case errorIs(err, scram.ErrIterationsUnsupported),
		errorIs(err, scram.ErrServerSignatureMismatch),
		errorIs(err, scram.ErrRejected):
		return err
	case errorIs(err, scram.ErrMalformedMessage),
		errorIs(err, scram.ErrMessageTooLarge):
		return ErrMalformedResponse
	case errorIs(err, scram.ErrUnexpectedResponse):
		return ErrNotKafka
	case errorIs(err, scram.ErrUsernameUnsupported):
		return ErrSCRAMUsernameUnsupported
	case errorIs(err, scram.ErrNoDerivation),
		errorIs(err, scram.ErrDerivationFailed),
		errorIs(err, scram.ErrDerivedKeyLength),
		errorIs(err, scram.ErrWrongStep):
		return ErrSCRAMLocalDerivation
	default:
		return err
	}
}

// printableASCII reports whether every byte of s is in U+0020..U+007E.
//
// # Why this is here rather than shared
//
// It inspects the **plaintext password**, and plaintext does not cross into
// internal/sasl/scram. That package holds an identical predicate for the
// username, which is not a secret; this one holds it for the password, which is.
// The duplication is the design: a shared helper would need the password as an
// argument, which is the one thing Model D exists to prevent.
//
// # Why the restriction exists, and why it is SCRAM-only
//
// RFC 5802 says a client SHOULD SASLprep the username, and RFC 4616 says the
// same for PLAIN. **Apache Kafka does neither** — KAFKA-6272 has been open since
// Kafka 1.0.0, and ScramFormatter.normalize() UTF-8 encodes and stops. So for
// non-ASCII input a SASLprep-correct client and a Kafka broker derive different
// keys and authentication fails, while PostgreSQL requires the opposite. Over
// printable ASCII SASLprep is provably the identity, so restricting to that
// range is correct against both.
//
// **SASL/PLAIN is deliberately not restricted.** PLAIN transmits the password
// verbatim and performs no client-side derivation, so there is nothing for a
// normalization disagreement to break: whatever the operator supplied is what
// the broker compares. SCRAM derives, and a mismatch would surface as the broker
// rejecting a correct credential. Harmonizing the two would narrow what PLAIN
// accepts for no benefit.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
