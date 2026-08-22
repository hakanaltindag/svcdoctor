// Package app composes one diagnostic run out of the production layers.
//
// It is the application-orchestration boundary docs/ARCHITECTURE.md section 3.2
// describes, and it is deliberately the smallest thing that can be called one:
// it sequences stages, owns the graph and the connections, and returns a
// canonical report. It holds no protocol knowledge, performs no I/O of its own,
// and decides nothing a probe, an adapter or a rule already decides.
//
// Everything here implements ADR 0041 and invents nothing.
//
// # The principle
//
//	discover broadly, authenticate narrowly
//
// A logical endpoint may resolve to several addresses, and every one of them may
// yield a usable connection. Above the credential boundary, measuring another
// path costs the target a connection; below it, measuring another path costs the
// target an authentication attempt — which is logged, counted, and in
// directory-backed deployments a step towards lockout (ADR 0028).
//
// So a run measures every path as far as credential-free discovery reaches, and
// then continues exactly one of them:
//
//	DNS -> TCP                              every resolved address
//	  -> SSLRequest -> TLS -> Startup       every completed path
//	  ---------------- credential boundary ----------------
//	  -> Authentication                     at most one path
//	  -> Session                            only the continued path
//	  -> Freeze -> Diagnosis -> LOCAL_FULL report
//
// # What it does not do
//
// No CLI, no flags, no exit codes: mapping a report to a process status belongs
// to the product boundary (docs/SCOPE.md). No rendering. **No redaction** — the
// run produces a LOCAL_FULL report and the output boundary derives a shareable
// one, which is why this package must never import internal/security/redaction.
// No service registry and no generic adapter interface: this is PostgreSQL
// composition, concretely, and ADR 0009 declines a speculative abstraction.
//
// It executes no SQL, opens no socket of its own, resolves no name, performs no
// TLS handshake and parses no protocol bytes. Guards in this package's tests
// enforce each of those rather than leaving them to habit.
package app
