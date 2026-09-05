package wire

import (
	"strings"

	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// CloseOutcome is a Connection.Close, normalized to a constant.
//
// It is the only thing a refusal's reply text contributes above this package.
// Every value is a literal declared in internal/service/rabbitmq; none is ever a
// slice of a peer's buffer. ADR 0069 section 3.
//
// # The vocabulary moved; the classification did not
//
// Phase 10.8B moved the type and its constants to internal/service/rabbitmq so
// that a diagnosis rule — which depguard forbids from importing this package —
// can recognize an outcome without respelling its literal. `normalizeClose` and
// everything below it stayed here, because that is protocol logic and a service
// vocabulary holds constants.
//
// These are **aliases, not copies**. There is one authoritative spelling of each
// value, so the two packages cannot drift, and every existing use of
// `wire.CloseVHostNotFound` and of `wire.CloseOutcome` is unchanged.
type CloseOutcome = servicerabbitmq.CloseOutcome

const (
	CloseUnspecified          = servicerabbitmq.CloseUnspecified
	CloseUnspecifiedTruncated = servicerabbitmq.CloseUnspecifiedTruncated
	CloseVHostNotFound        = servicerabbitmq.CloseVHostNotFound
	CloseVHostAccessRefused   = servicerabbitmq.CloseVHostAccessRefused
	CloseNodeConnectionLimit  = servicerabbitmq.CloseNodeConnectionLimit
	CloseVHostConnectionLimit = servicerabbitmq.CloseVHostConnectionLimit
	CloseUserConnectionLimit  = servicerabbitmq.CloseUserConnectionLimit
)

// truncationMarker is what Erlang's io_lib appends when {chars_limit, 255}
// shortens a formatted string. Measured, not assumed.
const truncationMarker = "..."

// normalizeClose classifies a Connection.Close reply text without parsing it.
//
// # Construct-and-compare, not matching
//
// svcdoctor renders each candidate sentence from **its own** vhost and username
// and compares for byte equality. It does not tokenize, does not scan for
// substrings and uses no regular expression. The peer's bytes are compared and
// discarded; nothing is extracted from them.
//
// That is not stylistic. Phase 8.0C reproduced two live defects in the prefix
// and infix matching Phase 8.0A had proposed:
//
//   - A vhost legally named `a': connection limit (5) is reached`, refused for
//     lack of permission, made an infix matcher report a capacity ceiling.
//   - A 119-byte vhost with an 80-byte username under a real capacity ceiling
//     produced a 255-byte truncated text whose discriminating suffix was gone,
//     and a prefix matcher reported an authorization denial.
//
// Construct-and-compare classified both correctly, and all ten measured texts.
//
// # Truncation is checked first
//
// A truncated string cannot be classified, because truncation removes exactly
// the suffix that discriminates. The exact templates also fail to match one, so
// this is belt-and-braces — but it runs first so the outcome names the reason.
//
// # Only T3 extends a prefix
//
// RabbitMQ's authorization backends may append `" by backend <module>: <reason>"`
// to a vhost denial, with the reason being arbitrary bytes. That is the one
// place the source proves an extension exists, and the extension only ever
// reaches a conclusion the bare template already supports, so allowing it adds
// no authority. Everything else is total equality.
func normalizeClose(replyCode uint16, text, vhost, username string) CloseOutcome {
	// The protocol bounds reply-text at 255 bytes. A longer field never reaches
	// here — readShortstr refuses it as malformed — so this is a second floor
	// rather than the only one.
	if len(text) > maxReplyText {
		return CloseUnspecified
	}

	// T0. First, and it short-circuits.
	if strings.HasSuffix(text, truncationMarker) {
		return CloseUnspecifiedTruncated
	}

	if replyCode != codeNotAllowed {
		// 403 at the authentication stage carries a sanitized sentence with no
		// distinction to extract, and 541 vhost-down was source-proven but never
		// live-measured, so ADR 0069 section 6.2 authorizes no normalization for
		// it. Both reach the weakest true conclusion.
		return CloseUnspecified
	}

	// The bare vhost-denial sentence, rendered from svcdoctor's own inputs. It
	// is the base of T2, T3 and T4.
	denial := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + username + "'"

	switch {
	// T1: RabbitMQ, vhost absent.
	case text == "NOT_ALLOWED - vhost "+vhost+" not found":
		return CloseVHostNotFound

	// T4: RabbitMQ, vhost capacity ceiling. Tested before T2, whose candidate is
	// this one's prefix.
	case matchesDigitHole(text, denial+": connection limit (", ") is reached"):
		return CloseVHostConnectionLimit

	// T2: RabbitMQ, vhost permission denied.
	case text == denial:
		return CloseVHostAccessRefused

	// T3: T2 with a backend's own reason appended. The only prefix rule.
	case strings.HasPrefix(text, denial+" by backend "):
		return CloseVHostAccessRefused

	// T5: RabbitMQ, node-wide capacity ceiling.
	case matchesDigitHole(text,
		"NOT_ALLOWED - connection refused: node connection limit (", ") is reached"):
		return CloseNodeConnectionLimit

	// T6: RabbitMQ, per-user capacity ceiling.
	case matchesDigitHole(text,
		"NOT_ALLOWED - connection refused for user '"+username+"': user connection limit (",
		") is reached"):
		return CloseUserConnectionLimit

	// L1: LavinMQ, vhost absent. Its sentence names no vhost, so the candidate
	// is a constant rather than a rendering.
	case text == "NOT_ALLOWED - vhost not found":
		return CloseVHostNotFound

	// L2: LavinMQ, vhost permission denied. Operands reversed relative to T2,
	// and it echoes the username — which is discarded here like every other
	// peer byte.
	case text == "NOT_ALLOWED - '"+username+"' doesn't have access to '"+vhost+"'":
		return CloseVHostAccessRefused

	// L3: LavinMQ, vhost capacity ceiling. Derived from LavinMQ's source rather
	// than measured in Phase 8.0C, and the LavinMQ fixture exercises it: if the
	// bytes differ, the scenario fails and this template is corrected against
	// the measurement rather than the source.
	case matchesDigitHole(text,
		"NOT_ALLOWED - access to vhost '"+vhost+"' refused: connection limit (",
		") is reached"):
		return CloseVHostConnectionLimit
	}

	return CloseUnspecified
}

// matchesDigitHole reports whether text is exactly prefix + digits + suffix.
//
// The hole is 1 to 20 ASCII digits at a fixed position between two literals.
// The value is **not parsed and not returned**: no integer from a peer becomes
// evidence, because "the limit is 200" is a fact about the broker's
// configuration that svcdoctor was not asked to report and cannot verify.
func matchesDigitHole(text, prefix, suffix string) bool {
	if len(text) < len(prefix)+len(suffix)+1 {
		return false
	}
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
		return false
	}
	middle := text[len(prefix) : len(text)-len(suffix)]
	if len(middle) < 1 || len(middle) > 20 {
		return false
	}
	for i := 0; i < len(middle); i++ {
		if middle[i] < '0' || middle[i] > '9' {
			return false
		}
	}
	return true
}

// The AMQP reply codes the frozen journey can observe.
//
// They are compared against, and the numeric value is carried on Refusal because
// it is the peer's own structured field rather than prose.
const (
	codeAccessRefused uint16 = 403
	codeNotAllowed    uint16 = 530
	codeInternalError uint16 = 541
)
