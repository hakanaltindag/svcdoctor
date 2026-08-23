package scram

// maxUsernameLen bounds the username this package will encode, before escaping.
//
// PostgreSQL role names cap at 63 bytes (NAMEDATALEN-1) and Kafka SCRAM
// principals are not tightly bounded, so 256 is generous for both while keeping
// the worst-case encoded form — every byte escaped, three bytes each — bounded
// at 768. Core policy, for the reason every bound here is: the two wire packages
// that call this one disagree about payload size by a factor of eight.
const maxUsernameLen = 256

// encodeSASLname prepares a username for the SCRAM "n=" attribute.
//
// # Escaping is RFC 5802 section 5.1 and it is mandatory
//
//	"," -> "=2C"
//	"=" -> "=3D"
//
// The RFC is explicit about the consequence of getting this wrong: *"If the
// server receives a username that contains '=' not followed by either '2C' or
// '3D', then the server MUST fail the authentication."* And an unescaped comma
// does more than malform the attribute list — it changes the AuthMessage that
// both sides sign, so the failure would surface as a signature mismatch rather
// than as the encoding fault it is.
//
// This is the code Phase 6.2a found missing. PostgreSQL never needed it because
// it sends an empty username; Kafka reads the principal from this field.
//
// # SASLprep is deliberately not implemented, and that is a correctness decision
//
// RFC 5802 section 5.1 says a client SHOULD SASLprep the username. Following it
// would be a defect here, because the two services svcdoctor speaks to disagree:
//
//   - PostgreSQL applies SASLprep on both sides. A client that skips it derives
//     a different key for non-ASCII input and the server answers 28P01 — a
//     correct credential reported as rejected. Measured on 14.24 and 18.6.
//   - Apache Kafka does not apply it. KAFKA-6272 has been open since Kafka
//     1.0.0: ScramFormatter.normalize() UTF-8 encodes and does nothing else. A
//     client that *does* SASLprep derives a different key and authentication
//     fails.
//
// The two require **opposite** behaviour for non-ASCII input, so no shared
// implementation is correct for both. Over printable ASCII, SASLprep is provably
// the identity — no mapping-table member is ASCII, NFKC is the identity because
// no ASCII code point decomposes and no ASCII pair composes, and the prohibited
// ASCII set is U+0000..U+001F with U+007F — so restricting to that range is the
// only choice correct against both, and it needs no Unicode dependency.
//
// Outside the range svcdoctor refuses, which is a truthful "svcdoctor cannot do
// this" rather than a false claim about the target. See ADR 0056 section 5.
//
// # The empty username is permitted, deliberately
//
// RFC 5802's saslname production is 1*(...), so "n=" with nothing after it is
// not grammatical, and section 5.1 says a client SHOULD abort on an empty
// prepared username. PostgreSQL requires exactly that: the role travels in the
// StartupMessage and the server ignores this attribute — verified against a real
// server with a deliberately wrong value, which still authenticated. Rejecting
// empty is therefore the **caller's** decision, not this package's, and Kafka
// makes it before calling Begin.
func encodeSASLname(user Username) (string, error) {
	if len(user) > maxUsernameLen {
		return "", ErrUsernameUnsupported
	}
	if !printableASCII(string(user)) {
		return "", ErrUsernameUnsupported
	}

	// Sized in one pass so the append below never grows, and so a username
	// needing no escaping allocates nothing at all.
	encoded := 0
	for i := 0; i < len(user); i++ {
		if user[i] == ',' || user[i] == '=' {
			encoded += 3
			continue
		}
		encoded++
	}
	if encoded == len(user) {
		return string(user), nil
	}

	out := make([]byte, 0, encoded)
	for i := 0; i < len(user); i++ {
		switch user[i] {
		case ',':
			out = append(out, '=', '2', 'C')
		case '=':
			out = append(out, '=', '3', 'D')
		default:
			out = append(out, user[i])
		}
	}
	return string(out), nil
}

// printableASCII reports whether every byte of s is in U+0020..U+007E.
//
// The loop is over bytes and that is exactly equivalent to a loop over code
// points here, with no decoding step: every code point at or above U+0080
// encodes in UTF-8 as bytes in 0x80..0xBF or 0xC2..0xF4, and none of those falls
// in 0x20..0x7E. Invalid UTF-8 is refused by the same test, which is the right
// answer — the guarantee being relied on is that SASLprep is the identity over
// this range, and an undecodable byte sequence is not in it.
//
// It is exported to neither package that calls this one. Each wire package keeps
// its own copy for the **password**, because a password is plaintext and
// plaintext does not cross into this package. That duplication is the design,
// not an oversight.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// printableRFC reports whether every byte of s is RFC 5802's "printable"
// production: %x21-2B / %x2D-7E.
//
// Narrower than printableASCII in both directions that matter: it excludes
// SPACE (0x20) and COMMA (0x2C). The comma exclusion is what makes a nonce
// unable to forge an attribute boundary, and while the attribute walker already
// splits on commas before this runs, checking it here means the property does
// not depend on the walker's behaviour.
func printableRFC(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 0x21 && c <= 0x2b) || (c >= 0x2d && c <= 0x7e) {
			continue
		}
		return false
	}
	return true
}
