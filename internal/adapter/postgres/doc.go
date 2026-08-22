// Package postgres diagnoses a PostgreSQL endpoint over one connection.
//
// It is the second service adapter and it owns three steps, in order, over the
// same socket the TCP probe measured:
//
//	Negotiate         postgres.ssl_request    L3  SSLRequest, and the TLS upgrade it may authorize
//	Startup           postgres.startup        L4  StartupMessage, and what authentication the peer demands
//	Authenticate      postgres.authentication L5  SCRAM-SHA-256, when the peer asks for it and policy allows
//	EstablishSession  postgres.session        L5  AuthenticationOk to ReadyForQuery, then Terminate
//
// Each step consumes the previous step's result and returns a new type, so the
// protocol state is in the type system rather than in a caller's memory: a
// Session cannot be authenticated, and an AuthenticatedSession cannot be
// authenticated twice.
//
// # It never dials
//
// Every step borrows a connection that generic transport established. Nothing
// here opens a socket, resolves a name, or performs a TLS handshake: the TLS
// upgrade after `SSLRequest` is performed by internal/probe/tls on the connection
// this package hands it, which is why the channel fact this package propagates is
// the probe's observation and not this package's inference (ADR 0029).
//
// **No path redials, retries, or falls back.** A failed exchange is evidence, and
// the connection is closed. `sslmode=prefer` is deliberately not reproduced: a
// TLS failure followed by a successful plaintext connection would swallow exactly
// the failures a diagnostic tool exists to find (ADR 0036 section 4).
//
// # Where the credential boundary is
//
// Authenticate is the only step that handles a credential, and it handles it in
// one order, which is the order of the code: the mechanism must be one svcdoctor
// performs, the channel must satisfy the transport policy, the logical endpoint
// must authorize the credential, and only then does a security.Secret reach
// internal/adapter/postgres/wire — the one package here that may call
// security.Reveal. Each step is a precondition for the next, so a refusal at any
// of them sends zero credential-derived bytes.
//
// **This package cannot call security.Reveal**, and a lint rule fails the build
// on an attempt. See ADR 0038 for the whole contract, including why success
// requires both a verified server signature and AuthenticationOk, and why a
// password outside printable ASCII is a gap in svcdoctor rather than a rejection
// by the peer.
//
// # Where SQLSTATE is interpreted
//
// **Each step has its own classifier and they must not be merged.** A shared
// PostgreSQL SQLSTATE dictionary would answer *what does this code mean*, when
// the only answerable question is *what does it prove here*: `3D000` proves a
// missing database at the session step and proves nothing at the two before it,
// because neither of those has sent a database name for a catalog lookup to fail
// on. `TestSQLStateMeaningIsScopedToItsStep` pins the difference and
// `TestEachStepHasItsOwnClassifier` makes merging them visible. See ADR 0039
// section 7.1.
//
// # What it does not do
//
// **It executes no SQL**, and an AST guard enforces that rather than a comment.
// Every fact the session step records arrives as a `ParameterStatus`; the one
// that would need a statement — the session-local `transaction_read_only` — is
// deferred as a fact rather than obtained by weakening the rule.
//
// The session step is terminal in v0.1: it sends `Terminate`, closes, and returns
// no connection, because nothing runs after `ReadyForQuery`.
package postgres
