// Package redis measures a Redis or Valkey endpoint over a connection generic
// transport established.
//
// It implements the journey ADR 0063 froze, and it implements no other. Three
// commands, one connection, at most one credential, and no key is ever named.
//
// # The journey
//
//	HELLO                     zero arguments, credential-free, on every path
//	  (Sentinel guard)        mode == sentinel stops the run before AUTH
//	AUTH                      at most once, on one selected path, policy-gated
//	HELLO                     again, only when the first was refused with NOAUTH
//	PING                      the terminal proof
//
// # Why the second HELLO is conditional rather than always
//
// `helloCommand` returns before it sets `c->resp` and before it builds the reply
// map when the connection is unauthenticated (redis/src/networking.c:5089-5100),
// so on a password-protected endpoint the first HELLO yields no identity, no
// mode and no role. Nothing else in the allowlist yields them, so the identity
// has to be asked for again after authentication — and only then. When the first
// HELLO answered, there is nothing a second one would add.
//
// # Discover broadly, authenticate narrowly
//
// HELLO runs on every completed transport path, because it is credential-free:
// measuring a second address costs the endpoint a connection and **not** an
// authentication attempt. That is what makes a per-address difference visible
// before any secret exists. Exactly one path then continues past the credential
// boundary, chosen by the composition root. This is the same shape ADR 0041 gave
// PostgreSQL and ADR 0050 gave Kafka, and it is an application decision that
// Redis inherits rather than a new one.
//
// # What this package must never do
//
//   - name a key, in any command, for any reason
//   - send a command outside HELLO, AUTH and PING
//   - put a credential in anything but AUTH
//   - present a credential more than once, retry it, or present it after a
//     re-dial, a redirect or a Sentinel detection
//   - read the text of a peer's error reply
//   - compare version strings, or branch on the implementation name
//   - follow MOVED or ASK, or ask anything about cluster topology
//
// Each of those has a structural test rather than only a convention.
package redis
