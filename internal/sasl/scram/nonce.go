package scram

import (
	"crypto/rand"
	"encoding/base64"
)

// rawNonceLen is the client nonce length in bytes before encoding.
//
// Eighteen matches libpq's SCRAM_RAW_NONCE_LEN, which matters twice: it is the
// shape every PostgreSQL-compatible server has been tested against, and it is
// divisible by three, so the base64 encoding is 24 characters with no "="
// padding to reconcile against RFC 5802's printable-character rule.
//
// # Base64 is kept, and that was measured rather than assumed
//
// Phase 6.2 briefly replaced this with an alphanumeric alphabet, on the theory
// that Apache Kafka's ClientFirstMessage regex constrains the nonce to
// [a-zA-Z0-9-] and would reject the "+" and "/" base64 produces. **That theory
// was tested against the real broker and is false**: Kafka 4.0.0 accepted
// nonces containing both characters and completed the exchange, verifier and
// all. The change was reverted rather than kept as a harmless extra, because a
// narrower alphabet defended by a wrong reason is worse than no change — the
// next reader would have believed the reason.
//
// RFC 5802's "printable" production is %x21-2B / %x2D-7E, which admits every
// base64 character including "+", "/" and "=", and excludes only the comma that
// would forge an attribute boundary. Both servers svcdoctor speaks to accept it.
const rawNonceLen = 18

// nonceSource produces one base64-encoded client nonce.
//
// It is an unexported function type rather than an exported interface on
// purpose, and it stays unexported after extraction. Deterministic nonces are
// needed to pin exact message bytes in a test, and that is the entire
// requirement; a public randomness abstraction would be a seam anybody could
// reach and a production caller could set.
//
// **The core owns nonce generation, and neither wire package may supply one.**
// ADR 0055 sketched a nonce parameter on Begin; ADR 0056 removed it, because a
// parameter puts entropy authority in two packages and makes a short,
// low-entropy or math/rand nonce a caller's mistake to make. One source, one
// length, tested once.
type nonceSource func() (string, error)

// cryptoNonce is the production source: 18 bytes of crypto/rand, base64-encoded.
//
// crypto/rand is the only entropy source in this package's import allowlist;
// math/rand and math/rand/v2 are absent from it, so a time-based or
// pseudo-random nonce is not reachable from here even by accident.
func cryptoNonce() (string, error) {
	var raw [rawNonceLen]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}
