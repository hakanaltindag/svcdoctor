// Package wire encodes and decodes the PostgreSQL frontend/backend protocol
// messages svcdoctor needs, and nothing else.
//
//	SSLRequest      -> one response byte           (S / N / E)
//	StartupMessage  -> the server's first reply     (AuthenticationXXX / ErrorResponse / …)
//
// It is the PostgreSQL counterpart of internal/adapter/kafka/wire and follows the
// same boundary: bytes in, plain Go values out. It holds no connection, produces
// no evidence, knows nothing about a graph, a layer, a failure class or a policy,
// and it never decides what an outcome means.
//
// # Zero dependencies
//
// The message surface svcdoctor needs is small enough to write directly, and
// ADR 0036 section 13 chose that over a library: every PostgreSQL client library
// that provides SCRAM also owns the connection lifecycle, `sslmode` fallback and
// multi-host failover — automatic redial and automatic fallback, the two
// behaviours ADR 0008 rejected. This package uses encoding/binary, io, net and
// context.
//
// # It borrows connections, never owns them
//
// Every function here takes a net.Conn and returns it unchanged. None of them
// closes one, and none of them dials. Whether a connection survives its exchange
// is an ownership decision, and it belongs to the caller (ADR 0021). Deadlines
// derived from the caller's context are cleared before returning, so a connection
// handed onward behaves as though nothing happened to it — which matters here
// more than it does for Kafka, because the connection this package writes an
// SSLRequest to is the same one a TLS handshake runs over next.
//
// # What it refuses to carry upward
//
// A decoded ErrorResponse leaves this package as an ErrorFields value holding a
// SQLSTATE and a non-localized severity. There is deliberately no field for the
// message, the detail, the hint, the schema, table, column or constraint name, or
// the server's source file and routine. **Structural absence is the mechanism**:
// a caller cannot leak a value this package never returns.
//
// That is not caution for its own sake. A real PostgreSQL `ErrorResponse`
// observed during the Phase 4.0 study carried, in one string, the role, the
// database, and svcdoctor's own NAT-translated source address as the server saw
// it — an address appearing nowhere else in the report, which structural
// redaction therefore cannot pseudonymize. See ADR 0036 section 6 and
// docs/validation/POSTGRES_PHASE4_PROTOCOL_STUDY.md section 4.2.
//
// # Errors are sentinels, never prose
//
// Failures come back as the sentinel errors below so that the adapter can
// classify them with errors.Is rather than by matching text. No network error's
// message, and no byte the peer sent, reaches an error this package returns.
package wire
