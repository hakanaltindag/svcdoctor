package scram

import (
	"encoding/base64"
	"strconv"
)

// Bounds this package enforces on everything a peer controls.
//
// **None of these is inherited from a caller, and that is the point.**
// internal/adapter/postgres/wire bounds a message at 1 MiB and
// internal/adapter/kafka/wire bounds a response at 8 MiB — eight times apart —
// so a core that trusted its caller's framing bound would be safe only for the
// callers that exist today. See ADR 0056 section 7.
const (
	// maxServerFirstLen bounds the whole server-first message before any
	// parsing happens. A real server-first is about ninety bytes: a nonce, a
	// base64 salt and an iteration count. 4096 leaves room for extensions and
	// still refuses a multi-megabyte message before the walker sees it.
	maxServerFirstLen = 4096

	// maxServerFinalLen bounds the whole server-final message. A real one is
	// about forty-six bytes.
	maxServerFinalLen = 4096

	// maxSaltEncodedLen bounds the salt **before base64 decoding**, and the
	// ordering is the reason it exists as a separate constant.
	//
	// The implementation this package was extracted from decoded the salt
	// before applying the iteration ceiling, so a peer able to send a Kafka-
	// sized frame could force roughly six megabytes of allocation before any
	// refusal. Bounding the encoded length first caps the decode at
	// maxSaltLen bytes: 4*ceil(128/3) rounds to 172.
	maxSaltEncodedLen = 172

	// maxSaltLen bounds the decoded salt. PostgreSQL uses sixteen bytes and
	// RFC 7677 sets no maximum; 128 is eight times the largest value in common
	// use.
	maxSaltLen = 128

	// maxNonceLen bounds the server nonce. The client half is 24 characters and
	// a server typically appends a similar amount, so real totals run 48 to 72.
	// The bound matters because the nonce enters the AuthMessage, which is
	// HMAC'd over its whole length.
	maxNonceLen = 256

	// maxAttributes bounds how many attributes the walker will visit. A
	// server-first carries three; the margin is for extensions. The walker
	// allocates nothing per attribute, so this bounds work rather than memory.
	maxAttributes = 16
)

// MaxIterations bounds the PBKDF2 work svcdoctor performs for one exchange.
//
// The server names the iteration count, so it is the only value in the exchange
// that decides how much CPU a diagnostic tool spends. PostgreSQL's
// scram_iterations is settable per session by any role with max_val 2147483647,
// and libpq validates only >= 1 with no ceiling at all. A peer answering with
// the maximum buys roughly eight minutes of PBKDF2, measured.
//
// 1048576 is 256 times PostgreSQL's default of 4096, sixteen times the highest
// value observed in a real configuration, and about a quarter of a second of
// work. A count above it is refused **before the derivation callback is
// reached**, which is the property the whole validation order exists to hold.
//
// The numeric bound is core policy because it protects svcdoctor's CPU, which is
// service-independent. Mapping the refusal into evidence belongs to each
// adapter. See ADR 0038 section 16 and ADR 0056 section 7.
const MaxIterations = 1 << 20

// serverFirst is a validated server-first message. Every field has passed every
// check in the validation order before this value exists.
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
// Every rule is a refusal to continue rather than a warning:
//
//   - r, s and i are all required, and each may appear exactly once.
//   - The server nonce must be RFC 5802 "printable", within maxNonceLen, and
//     must **strictly extend** the client nonce: the prefix must match and the
//     result must be longer. RFC 5802 section 5 requires the prefix check; the
//     length check is separate because a nonce equal to the client's adds no
//     server entropy and defeats the replay protection the nonce exists for.
//   - The salt must be within maxSaltEncodedLen **before** it is decoded, must
//     be valid standard base64, and must be within maxSaltLen after.
//   - The iteration count must be a positive decimal integer within
//     MaxIterations.
//   - A mandatory extension ("m") must be refused, as RFC 5802 section 5.1
//     requires: its presence "MUST cause authentication failure when the
//     attribute is parsed by the other end".
//
// Unrecognized non-mandatory attributes are ignored, which is what the RFC's
// extension rule asks for.
func parseServerFirst(raw, clientNonce string) (serverFirst, error) {
	if len(raw) > maxServerFirstLen {
		return serverFirst{}, ErrMessageTooLarge
	}

	var (
		haveR, haveS, haveI      bool
		nonce, saltText, iterStr string
	)

	err := attributes(raw, func(key byte, value string) error {
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

	if len(nonce) > maxNonceLen {
		return serverFirst{}, ErrMessageTooLarge
	}
	if !printableRFC(nonce) {
		return serverFirst{}, ErrMalformedMessage
	}
	// Strictly extending: the prefix must be svcdoctor's own nonce, and the
	// result must be longer. Compared as an exact slice equality against a value
	// this process generated, never as a search through peer-chosen text.
	if len(nonce) <= len(clientNonce) || nonce[:len(clientNonce)] != clientNonce {
		return serverFirst{}, ErrMalformedMessage
	}

	// The encoded bound precedes the decode, so the allocation below is bounded
	// by maxSaltLen rather than by the message size.
	if len(saltText) > maxSaltEncodedLen {
		return serverFirst{}, ErrMessageTooLarge
	}
	salt, err := base64.StdEncoding.DecodeString(saltText)
	if err != nil {
		return serverFirst{}, ErrMalformedMessage
	}
	if len(salt) > maxSaltLen {
		return serverFirst{}, ErrMessageTooLarge
	}

	iterations, err := parseIterations(iterStr)
	if err != nil {
		return serverFirst{}, err
	}

	return serverFirst{nonce: nonce, salt: salt, iterations: iterations}, nil
}

// attributes walks the comma-separated `k=v` attributes of a SCRAM message.
//
// # Why this is hand-written rather than a strings.Split
//
// Two reasons, and the second is the load-bearing one. A classifier that reads
// prose makes confident claims about bytes the peer chose, which the repository
// forbids in every production file that interprets a reply. And strings is not
// in this package's import allowlist at all, so the scan below is not a
// stylistic preference — it is the only way to do this here.
//
// The scan is a byte-level grammar walk: a comma delimiter, an `=` separator and
// single-letter keys, all fixed by RFC 5802. It allocates nothing per attribute;
// every value is a slice of the input string.
//
// An attribute shorter than two bytes, or whose second byte is not `=`, is
// malformed: the sender announced a grammar it did not follow.
func attributes(raw string, visit func(key byte, value string) error) error {
	for seen := 0; ; seen++ {
		if seen >= maxAttributes {
			return ErrMalformedMessage
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
// where its report would be most useful. The count is returned so a caller can
// record it and a rule can say so later.
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
	if n > MaxIterations {
		return 0, ErrIterationsUnsupported
	}
	return int(n), nil
}
