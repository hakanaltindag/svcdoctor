// Package diagnosis turns normalized evidence into findings.
//
// It is a pure transformation:
//
//	immutable domain.Graph -> rules -> []domain.Finding
//
// Nothing here performs I/O. It does not call probes or adapters, resolve names,
// open sockets, read files or the environment, run commands, discover topology,
// retry, or schedule work. It reads a frozen graph and returns values. See
// docs/ARCHITECTURE.md section 6, which is enforced by the depguard rules in
// .golangci.yml rather than left to discipline.
//
// # What it does not produce
//
// Diagnosis produces findings and stops there. It does not assemble a report,
// derive a summary, or map anything to an exit code. Those belong to the report
// and the CLI; see ADR 0015 and docs/SCOPE.md.
//
// It also does not validate that a finding's evidence references resolve to
// nodes in the graph. A rule should not knowingly produce a dangling reference,
// but the authoritative check stays where both sides are owned, which is report
// construction. See ADR 0014.
//
// # Service neutrality
//
// The engine evaluates rules. It never branches on a service name, and it holds
// no protocol knowledge. Cross-service transport rules belong in
// internal/diagnosis/transport, and service rules in internal/diagnosis/<service>,
// per docs/ARCHITECTURE.md section 6. Both are just rules to the engine.
//
// # Why this package ships no rules yet
//
// Phase 1.5 implements the contract and the engine and deliberately implements no
// concrete rules. Writing one would require choosing a Severity, and Severity is
// impact, which the repository does not yet define for a transport failure.
//
// The reason is specific rather than a lack of effort. Whether a failed DNS
// lookup or a refused connection prevents correct use depends on whether the
// endpoint was the one the user asked about or one discovered from it. That
// distinction is Origin, which ADR 0013 deliberately defers until topology
// orchestration exists. Assigning a severity today would either hardcode one
// answer for both cases or invent a policy no document states.
//
// A second gap points the same way: docs/FINDINGS.md section 5 forbids
// manufacturing downstream failure findings, but nothing yet says how a generic
// transport rule and a service rule avoid both reporting the same failed
// endpoint. See ADR 0017 and docs/BACKLOG.md.
package diagnosis
