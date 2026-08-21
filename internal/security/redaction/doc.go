// Package redaction turns a local report into one that is safe to share.
//
//	LOCAL_FULL domain.Report -> Redact -> SHAREABLE_REDACTED domain.Report
//
// # It is a structural transformation, not a diagnosis
//
// Redaction reads an already-valid canonical report and builds another one. It
// creates no findings, changes no severity, confidence, kind, state, failure
// class or graph relationship, and performs no I/O of any sort. It does not
// mutate its input: the local report a caller passes in is unchanged and still
// says LOCAL_FULL afterwards.
//
// The output is rebuilt through the ordinary domain constructors, so it passes
// the same validation any report does, including the ADR 0014 evidence-reference
// check and the derived summary of ADR 0015. Nothing here reaches around a domain
// invariant.
//
// # Preserve correlation, remove identity
//
// Blanking every identifier would make a shareable report useless. A reader must
// still be able to see that the same host appears in the target, in three
// evidence subjects and in a finding, so each distinct value maps to one stable
// pseudonym everywhere it occurs:
//
//	kafka.prod.internal -> host-001
//	10.20.30.40         -> ip-001
//
// Assignment is deterministic and does not depend on traversal or map order: all
// values are collected, sorted, then numbered. See ADR 0018.
//
// # Why this package sits under internal/security
//
// docs/SECURITY.md gives the security package ownership of redaction, and this
// is a subpackage of it rather than part of it. internal/security stays a leaf
// with no internal dependencies, while this package imports internal/domain.
// Keeping them separate leaves domain free to import internal/security later for
// masked value types, which the architecture allows, without creating a cycle.
//
// The report holds no security.Secret and no security.Credential, so this package
// needs nothing from internal/security and never calls security.Reveal.
//
// # Known limit
//
// An attribute value that carries identity in a shape this package cannot
// recognize structurally, and that appears nowhere else in the report, is
// preserved. The evidence model has no per-key sensitivity classification, and
// adding one is tied to the open question of where service attribute keys live.
// See ADR 0018 and docs/BACKLOG.md.
package redaction
