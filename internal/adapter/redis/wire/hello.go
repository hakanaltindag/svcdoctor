package wire

import (
	"context"
	"fmt"
	"time"
)

// The server modes and replication roles svcdoctor recognizes.
//
// Both are closed sets, for the same reason the error prefixes are: the value
// arrives from the peer, and a value svcdoctor did not anticipate must become
// "unknown" rather than become a string in the report. Redis emits exactly these
// (redis/src/networking.c:5118-5124) and Valkey emits the same, including
// "master" rather than "primary".
const (
	ModeUnknown    = ""
	ModeStandalone = "standalone"
	ModeCluster    = "cluster"
	ModeSentinel   = "sentinel"

	RoleUnknown = ""
	RoleMaster  = "master"
	RoleReplica = "replica"
)

// maxIdentityLen bounds the peer-supplied identity strings svcdoctor retains.
//
// server and version are genuinely open strings — an implementation may call
// itself anything — so unlike mode and role they cannot be validated against a
// closed set. They are bounded and charset-checked instead.
//
// A value that fails either check is recorded as **absent**, never truncated.
// Truncating would put a value in the report that no peer ever sent, which is
// the same class of invention as guessing a cause from an error message.
//
// 128 is the width at which a value stops being an identifier: measured, Redis
// 8.2.1 sends "redis"/"8.2.1" and Valkey 8.1.1 sends "valkey"/"8.1.1".
const maxIdentityLen = 128

// Hello is the normalized outcome of one zero-argument HELLO.
//
// Only the fields ADR 0066 section 4 authorizes are here. `id` and `modules` are
// parsed and discarded: `id` is a server-internal correlation handle no BASIC
// rule reads, and `modules` is the one unbounded field in the reply — 542 of the
// 688 bytes Redis 8.2.1 sends — that would create an expectation svcdoctor
// assesses module health.
type Hello struct {
	// Prefix is PrefixNone when the endpoint answered with the reply array, and
	// the normalized condition when it answered with an error.
	Prefix ErrorPrefix

	// Server and Version are what the endpoint *said*, never what it is.
	//
	// Valkey reports "valkey" by default and "redis" with a Redis version number
	// when extended-redis-compat is on (valkey/src/networking.c:5937), so these
	// are observations about a configurable self-description. Empty means the
	// field was absent, unparseable, or failed the identity checks above.
	Server  string
	Version string

	// Proto is the RESP version the connection is on. A zero-argument HELLO does
	// not change it (redis/src/networking.c:5100 sets c->resp only when a
	// version was supplied), so this reports 2 on every svcdoctor connection and
	// is recorded as the measured fact rather than assumed.
	Proto int64

	// Mode is one of the closed set above. ModeUnknown means the endpoint sent
	// something else or nothing.
	Mode string

	// Role is one of the closed set above.
	//
	// **Absent is meaningful.** Redis omits the field entirely in sentinel mode
	// (redis/src/networking.c:5122 emits it only when !server.sentinel_mode), so
	// RoleUnknown alongside ModeSentinel is a corroborating signal rather than a
	// gap.
	Role string
}

// Answered reports that the endpoint returned the reply array rather than an
// error.
func (h Hello) Answered() bool { return h.Prefix == PrefixNone }

// AuthRequired reports that the endpoint refused HELLO because the connection is
// not authenticated.
//
// This is the credential-free half of the journey doing its work: the endpoint's
// own answer, obtained before any secret was assembled, tells svcdoctor whether
// a credential is needed at all. ADR 0064 section 6 also relies on it to recover
// the one fact prefix-only classification would otherwise lose — an endpoint that
// answers HELLO with the reply array requires no authentication, which is the
// meaning of the `ERR AUTH ... called without any password configured` text that
// svcdoctor deliberately does not read.
func (h Hello) AuthRequired() bool { return h.Prefix == PrefixNOAUTH }

// Unsupported reports that the endpoint does not implement HELLO.
//
// Redis before 6.0, a proxy, or a deployment that renamed the command. The
// endpoint answers `-ERR unknown command 'HELLO'` — and, because svcdoctor sent
// no arguments, the argument echo at redis/src/server.c:4386 has nothing to
// disclose.
//
// **It is decided on the prefix plus the step, never on the message text.** ERR
// is the generic prefix, so this is not "the text said unknown command"; it is
// "the endpoint refused HELLO generically", which at this step means it does not
// implement it. Nothing downstream may read more into it than that.
func (h Hello) Unsupported() bool { return h.Prefix == PrefixERR }

// SendHello performs the zero-argument HELLO exchange.
//
// The frame is a package constant. It cannot acquire a protocol version, an AUTH
// clause or a SETNAME clause, which is what makes the credential-echo defect
// structurally absent rather than merely avoided.
func (c *Conn) SendHello(ctx context.Context, timeout time.Duration) (Hello, error) {
	r, err := c.exchange(ctx, timeout, helloFrame)
	if err != nil {
		return Hello{}, err
	}

	switch r.kind {
	case kindError:
		return Hello{Prefix: classifyErrorText(r.text)}, nil
	case kindArray:
		if r.null {
			return Hello{}, fmt.Errorf("%w: HELLO answered with a null array", ErrUnexpectedReply)
		}
		return normalizeHello(r.array)
	default:
		return Hello{}, fmt.Errorf("%w: HELLO answered with a non-array reply", ErrUnexpectedReply)
	}
}

// normalizeHello turns the RESP2 flat key/value array into the authorized
// fields.
//
// # Unknown fields are skipped, never rejected
//
// Valkey adds availability_zone when it is configured, and a future version of
// either implementation may add more. A parser that failed on an unknown key
// would turn a compatible server into a diagnostic failure, so unrecognized keys
// are read past and discarded — including their values, whatever shape those
// take.
func normalizeHello(items []reply) (Hello, error) {
	if len(items)%2 != 0 {
		return Hello{}, fmt.Errorf("%w: HELLO reply has %d elements, which is not key/value pairs",
			ErrUnexpectedReply, len(items))
	}

	var out Hello
	for i := 0; i < len(items); i += 2 {
		key, ok := stringValue(items[i])
		if !ok {
			// A non-string key is not something Redis produces. Skipping keeps
			// the parser total: the fields svcdoctor wants are still found, and
			// nothing is invented for the ones it cannot read.
			continue
		}
		value := items[i+1]

		switch key {
		case "server":
			out.Server = identityValue(value)
		case "version":
			out.Version = identityValue(value)
		case "proto":
			if value.kind == kindInteger {
				out.Proto = value.integer
			}
		case "mode":
			out.Mode = closedValue(value, ModeStandalone, ModeCluster, ModeSentinel)
		case "role":
			out.Role = closedValue(value, RoleMaster, RoleReplica)
		default:
			// id, modules, availability_zone and anything added later. Read and
			// discarded, deliberately: see the Hello doc comment.
		}
	}
	return out, nil
}

// stringValue returns a simple or bulk string, if that is what the frame holds.
func stringValue(r reply) (string, bool) {
	switch r.kind {
	case kindSimpleString:
		return r.text, true
	case kindBulk:
		if r.null {
			return "", false
		}
		return string(r.bulk), true
	default:
		return "", false
	}
}

// identityValue returns a peer-supplied open string, or empty if it is not one
// svcdoctor will retain.
//
// Printable ASCII only, and bounded. A control byte in an identity value would
// reach a terminal renderer, and a long one would reach a report row; neither is
// something a server name or a version number legitimately contains.
func identityValue(r reply) string {
	s, ok := stringValue(r)
	if !ok || s == "" || len(s) > maxIdentityLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

// closedValue returns the peer's value only when it is one of the allowed
// constants, and returns the constant rather than the peer's bytes.
//
// Returning `allowed[i]` rather than `s` is deliberate: the value in the report
// is then provably one this package declared, so no peer-chosen byte can reach
// the graph even in the matching case.
func closedValue(r reply, allowed ...string) string {
	s, ok := stringValue(r)
	if !ok {
		return ""
	}
	for _, a := range allowed {
		if s == a {
			return a
		}
	}
	return ""
}
