// Package wire speaks RESP2 to a Redis or Valkey endpoint and normalizes what
// comes back.
//
// It is the narrowest boundary in the Redis adapter and the only place that
// touches peer bytes. Nothing here builds evidence, decides a state, names a
// failure class or knows what a finding is: it reads frames, refuses the ones it
// will not spend memory on, and hands the caller normalized values.
//
// # Three commands, and no fourth
//
// ADR 0063 section 2 freezes the allowlist at HELLO, AUTH and PING. Every
// outbound byte this package can produce comes from one of encodeHello,
// encodeAuth or encodePing, and TestOnlyThreeCommandsCanBeEncoded asserts that
// no fourth encoder exists. A command outside the allowlist is not merely unused
// here; it cannot be written.
//
// **No command this package sends names a key.** That is what makes MOVED, ASK
// and CLUSTERDOWN structurally unreachable rather than merely unhandled: a
// keyless command is never cluster-redirected (redis/src/server.c:4609-4616), so
// ADR 0065 gives those codes no owner.
//
// # HELLO carries zero arguments, always
//
// The frame is exactly:
//
//	*1\r\n$5\r\nHELLO\r\n
//
// and TestHelloFrameIsExactlyTheZeroArgumentForm compares it byte for byte.
//
// This is a security mechanism, not a style. When HELLO is unknown — a server
// before 6.0, a proxy, a deployment that renamed it — Redis echoes up to 128
// bytes of the command's *arguments* back to the caller and into its own log
// (redis/src/server.c:4378-4389), and the redaction that would prevent it lives
// inside helloCommand and therefore never runs on that path. A HELLO with no
// arguments has nothing to leak. See ADR 0064 sections 1 and 3.
//
// # Exactly one function reveals a secret
//
// authenticate is the only production caller of security.Reveal in this package
// and the third in the repository. ADR 0027's confinement is unchanged and
// forbidigo enforces it.
//
// # Raw peer text stops here
//
// A Redis error message interpolates whatever the caller sent
// (redis/src/server.c:4386) and, for NOPERM, the username
// (redis/src/acl.c:2871). None of it leaves this package. The only thing that
// crosses the boundary is a normalized ErrorPrefix drawn from a closed set, with
// everything unrecognized collapsing to PrefixUnrecognized. See ADR 0066 and
// errors.go.
//
// # RESP2 only
//
// ADR 0063 section 6 freezes the protocol at RESP2, and this package implements
// six frame forms and refuses every RESP3 first byte as malformed. That is not
// laziness about RESP3; it is what makes push frames and attribute frames
// unreachable rather than handled, because neither can arrive on a connection
// that never sent HELLO with a protocol version and never subscribed.
package wire
