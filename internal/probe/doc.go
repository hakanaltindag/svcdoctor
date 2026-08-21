// Package probe holds the vocabulary that every generic transport probe shares.
//
// Its subpackages — dns, tcp and later tls — collect the facts. This package
// exists only for the few things all of them must agree on, and it earned its
// existence when the second probe arrived: identifier encoding is a contract
// between probes, and two copies of it would drift.
//
// # What belongs here
//
// A rule that would be wrong if two probes implemented it differently. Today that
// is exactly one thing: how an evidence identifier is built (ADR 0019).
//
// # What must never be put here
//
// This package must not become the generic layer the architecture deliberately
// does not have:
//
//   - No Probe interface. DNS, TCP and TLS take different inputs and produce
//     different facts; a shared shape imposed on them would be invented, not
//     discovered. See ADR 0020.
//   - No registry, factory, plugin lookup or dependency-injection helper.
//   - No orchestration. Sequencing probes, deciding that a failed lookup blocks a
//     connection attempt, and recording graph relationships belong to the
//     transport chain, which does not exist yet.
//   - No service knowledge, ever.
//   - No shared attribute vocabulary until two probes genuinely need the same
//     key. As of Phase 2.2 they do not: dns.answers has one consumer and the TCP
//     probe records no attributes at all.
//
// A helper that only one probe uses belongs in that probe.
package probe
