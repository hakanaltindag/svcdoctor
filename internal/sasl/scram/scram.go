package scram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// MechanismSHA256 is the SASL mechanism name this package implements.
//
// One constant, one meaning. Each wire package re-exports it under the name its
// adapter already uses, so the string a mechanism check compares against and the
// string an exchange frames are the same value.
const MechanismSHA256 = "SCRAM-SHA-256"

// DerivedKeyLen is the exact length Derive must return, in bytes.
//
// SHA-256 output. See ErrDerivedKeyLength for what checking it proves and, more
// importantly, what it does not.
const DerivedKeyLen = sha256.Size

// GS2Header is the GS2 header a SCRAM-SHA-256 exchange sends, and it is not
// negotiable.
//
// RFC 5802 section 5 defines "n" as *"client doesn't support channel binding"*,
// which is the truthful statement for this implementation, and PostgreSQL
// accepts it unconditionally — including over TLS with SCRAM-SHA-256-PLUS first
// in the advertised list.
//
// "y" is **never** sent. It means "I support channel binding but I think you do
// not", which is a downgrade claim, and a real PostgreSQL server refuses it with
// 28000 when it does offer -PLUS. The authorization identity is absent rather
// than empty-and-present, because PostgreSQL rejects any authzid outright with
// 0A000.
//
// # Why this is exported when almost nothing else is
//
// Begin returns the client-first-**bare**, so the caller prepends this header
// when it frames the first message, while Continue computes the channel-binding
// value from the same constant. Exporting it is what makes those two uses one
// value: a wire package holding its own copy of "n,," could drift from the
// header this package signs into the AuthMessage, and the failure would surface
// as a signature mismatch rather than as the disagreement it is.
const GS2Header = "n,,"

// Username is the authentication identity, before SASLname escaping.
//
// It is a named type so that passing a password here is an explicit, greppable
// conversion rather than an ordinary string argument. **That is a speed bump,
// not a guarantee**: no API that accepts a username can structurally tell one
// string from another. What actually catches the mistake is review, the RFC
// vectors and integration. ADR 0056 section 11 records this as a residual risk
// rather than pretending it is closed.
type Username string

// Derive turns a credential this package never sees into a SCRAM
// SaltedPassword.
//
// The caller supplies it, closing over plaintext that stays in the caller's
// package, and performs PBKDF2 there. **This package calls it exactly once, only
// after every check in the validation order has passed, and never retains it.**
//
// salt is borrowed for the duration of the call: this package does not read it
// again afterwards, so mutation is harmless, but it must not be retained.
//
// The returned slice must be exactly DerivedKeyLen bytes. An error is collapsed
// into ErrDerivationFailed and never wrapped — see that sentinel for why.
type Derive func(salt []byte, iterations int) ([]byte, error)

// step is where an exchange has got to.
//
// It exists so that driving the exchange out of order is an error rather than a
// silent wrong answer, which removes two entries from the mutation matrix for
// one unexported field and three comparisons. It is not a general state-machine
// abstraction and must not become one.
type step uint8

const (
	stepBegun step = iota
	stepContinued
	stepDone
	stepFailed
)

// State is one in-progress SCRAM-SHA-256 exchange.
//
// Use it only through the pointer Begin returns; it is not safe to copy. There
// is deliberately no String, GoString or Format method, and no exported field.
//
// # What it never holds
//
// No plaintext password, no security.Secret, no security.Credential, no Derive
// callback, no net.Conn, no endpoint, no service identity and no logger. Several
// of those are unnameable here because the packages that define them are not in
// this package's import allowlist; the rest are asserted by guards_test.go.
//
// # What it holds, and for how long
//
// The state is minimized at each step, so the window in which any value exists
// is the shortest one the protocol allows:
//
//	after Begin      clientFirstBare, clientNonce, step
//	after Continue   expectedServerSignature, step
//	after Verify     step
//
// Continue computes both the client proof and the expected server signature from
// the AuthMessage and then drops the AuthMessage, the SaltedPassword, ClientKey,
// StoredKey, ServerKey, the client-first-bare and both nonces. Verify needs only
// a 32-byte comparison, so nothing else survives it.
type State struct {
	step step

	// clientFirstBare and clientNonce live only between Begin and Continue.
	// Both are credential-adjacent authentication material and neither leaves
	// this package.
	clientFirstBare string
	clientNonce     string

	// expectedServerSignature lives only between Continue and Verify. It is
	// credential-derived: it is HMAC(ServerKey, AuthMessage), and ServerKey
	// derives from the SaltedPassword.
	expectedServerSignature []byte
}

// Begin starts an exchange and returns the client-first-bare message.
//
// The returned string is `n=<escaped username>,r=<nonce>`. It is the **bare**
// message: the caller prepends GS2Header when it frames the first message, and
// this package keeps the bare form because that is what RFC 5802 signs into the
// AuthMessage.
//
// The nonce is generated here. There is no parameter for it, deliberately — see
// nonceSource.
func Begin(user Username) (*State, string, error) {
	return begin(user, cryptoNonce)
}

// begin is the deterministic-nonce core, for this package's own vector tests.
func begin(user Username, nonces nonceSource) (*State, string, error) {
	encoded, err := encodeSASLname(user)
	if err != nil {
		return nil, "", err
	}

	nonce, err := nonces()
	if err != nil {
		return nil, "", err
	}

	bare := "n=" + encoded + ",r=" + nonce
	return &State{step: stepBegun, clientFirstBare: bare, clientNonce: nonce}, bare, nil
}

// Continue validates the server-first message, derives through the caller's
// callback, and returns the client-final message.
//
// # The validation order is the security property
//
// Every check below happens before the callback is reached, and each failure
// returns without ever evaluating it:
//
//  1. the state is in the post-Begin step
//  2. a callback was supplied
//  3. the whole message is within maxServerFirstLen — checked before parsing
//  4. the attribute count is within maxAttributes
//  5. every attribute follows the `k=v` grammar
//  6. no mandatory extension "m" is present
//  7. no duplicate r, s or i
//  8. r, s and i are all present
//  9. the server nonce is within maxNonceLen and is RFC "printable"
//  10. the server nonce strictly extends the client nonce
//  11. the encoded salt is within maxSaltEncodedLen — checked before decoding
//  12. the salt is valid base64 and within maxSaltLen once decoded
//  13. the iteration count is all digits, parses, is > 0, and is <= MaxIterations
//
// Only then is derive evaluated, and it is evaluated **exactly once**: there is
// one call expression in this package, it is not inside any loop or goroutine,
// and the step check above makes a second Continue an error before any of this
// runs.
func (s *State) Continue(serverFirst string, derive Derive) (string, error) {
	if s.step != stepBegun {
		return "", ErrWrongStep
	}
	if derive == nil {
		s.step = stepFailed
		return "", ErrNoDerivation
	}

	first, err := parseServerFirst(serverFirst, s.clientNonce)
	if err != nil {
		s.step = stepFailed
		return "", err
	}

	// Everything the peer chose has now been validated, including the iteration
	// ceiling, so no PBKDF2 can be provoked by a message this package refuses.
	salted, deriveErr := derive(first.salt, first.iterations)
	if deriveErr != nil {
		s.step = stepFailed
		return "", ErrDerivationFailed
	}
	if len(salted) != DerivedKeyLen {
		s.step = stepFailed
		return "", ErrDerivedKeyLength
	}

	clientFinal, expected := s.finish(serverFirst, first, salted)

	// Minimize: everything the proof was built from is dropped, and only the
	// 32 bytes Verify compares survive.
	s.clientFirstBare = ""
	s.clientNonce = ""
	s.expectedServerSignature = expected
	s.step = stepContinued
	return clientFinal, nil
}

// Verify checks that the peer proved knowledge of the credential.
//
// **This is mandatory and it is the half of the exchange that authenticates the
// server.** RFC 5802 section 5: *"If the two are different, the client MUST
// consider the authentication exchange to be unsuccessful."* A peer that
// announces success without getting here has proved nothing.
func (s *State) Verify(serverFinal string) error {
	if s.step != stepContinued {
		return ErrWrongStep
	}

	if err := verifyServerFinal(serverFinal, s.expectedServerSignature); err != nil {
		s.expectedServerSignature = nil
		s.step = stepFailed
		return err
	}

	s.expectedServerSignature = nil
	s.step = stepDone
	return nil
}

// finish computes the client proof and the signature the server must produce.
//
// Straight RFC 5802 section 3 with SHA-256, from the standard library only. The
// channel-binding value is computed from GS2Header rather than written as the
// constant "biws", so it cannot silently stop matching if the header ever
// changes — and the server includes that header in the value it verifies.
//
// **Nothing computed here leaves this function except the two values returned**,
// and neither of those leaves the exchange: the proof goes to the caller for the
// socket and the expected signature is compared and discarded.
func (s *State) finish(serverFirstRaw string, first serverFirst, salted []byte) (string, []byte) {
	clientKey := mac(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	channelBinding := base64.StdEncoding.EncodeToString([]byte(GS2Header))
	withoutProof := "c=" + channelBinding + ",r=" + first.nonce
	authMessage := s.clientFirstBare + "," + serverFirstRaw + "," + withoutProof

	clientSignature := mac(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}

	serverKey := mac(salted, []byte("Server Key"))
	expected := mac(serverKey, []byte(authMessage))

	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), expected
}

// mac is HMAC-SHA-256.
func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// verifyServerFinal checks the server-final message against the expected
// signature.
//
// # Only the first attribute decides, and that is preserved deliberately
//
// RFC 5802 permits trailing extensions after the verifier or the error, so a
// message like `v=<valid>,x=ignored` is well-formed and must be accepted. This
// implementation reads the first attribute and stops, which is the behaviour
// extracted from internal/adapter/postgres/wire unchanged.
//
// A stricter reading — rejecting a message carrying both `v=` and `e=`, or a
// duplicate of either — was considered during Phase 6.2 and **deliberately not
// adopted**. No PostgreSQL or pgBouncer version observed sends either shape, so
// the change would be invisible against real servers; but it would still alter
// what this function returns for `v=<valid>,e=<token>`, and ADR 0056 section 8
// forbids changing PostgreSQL semantics during extraction without a separate
// decision. The shapes are pinned by test at the behaviour that ships.
//
// # The error attribute is read and never kept
//
// RFC 5802 defines server-error-value as a token list *with* an extension
// production, so the token is not guaranteed to come from the closed set and a
// peer may put arbitrary text there. It is compared against exact tokens to
// choose a sentinel and then dropped: it reaches no field, no error and no
// evidence.
func verifyServerFinal(raw string, expected []byte) error {
	if len(raw) > maxServerFinalLen {
		return ErrMessageTooLarge
	}

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
			// Neither is read for its cause — the two are one outcome here.
			return ErrRejected
		case "invalid-username-encoding":
			// **Not a credential refusal.** RFC 5802 defines this as the
			// username field failing SASLprep or `=`-escaping, which is a fault
			// in the value's encoding rather than a decision about the material.
			// Calling it a rejection would let a decoding fault reach diagnosis
			// as "the peer refused your credential".
			return ErrUnexpectedResponse
		default:
			return ErrUnexpectedResponse
		}
	case 'v':
		signature, err := base64.StdEncoding.DecodeString(attr[2:])
		if err != nil {
			return ErrMalformedMessage
		}
		// hmac.Equal, never == or bytes.Equal: the comparison is against a
		// value derived from the credential and must not leak through timing.
		if !hmac.Equal(signature, expected) {
			return ErrServerSignatureMismatch
		}
		return nil
	default:
		return ErrMalformedMessage
	}
}
