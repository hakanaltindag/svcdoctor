// Package scram implements the RFC 5802 SCRAM-SHA-256 client exchange, and
// nothing else.
//
// # What this package cannot do
//
// It cannot observe a reusable credential. **No function here accepts a
// password, in any type**, and there is no argument a caller could pass one to.
// That is the whole point of the design, and it is structural rather than
// enforced: ADR 0055 rejected a shared core that took plaintext as an argument
// precisely because such a core's safety would have to be maintained by lint
// and review forever, while this one's is a property of its signatures.
//
// The caller supplies a Derive callback instead. This package validates
// everything the peer chose — the message size, the attribute grammar, the
// nonce, the salt and the iteration count — and only then asks the caller to
// turn a password it never sees into a SaltedPassword. See ADR 0056.
//
// It also cannot import internal/security, net, fmt, strings, a logger or any
// other svcdoctor package; it performs no I/O; it holds no connection, endpoint
// or service identity; and it knows nothing about PostgreSQL or Kafka framing.
// A depguard allowlist and TestSharedCoreImportsAreExactlyTheAllowlist enforce
// the import set, and the guards in guards_test.go enforce the rest.
//
// # What crosses the boundary
//
// The SaltedPassword, inbound, for the duration of one call. It is
// credential-derived and sensitive — it authenticates this principal to this
// server for this salt, and both StoredKey and ServerKey derive from it — but it
// is not the operator's reusable password. That is the exact threat reduction
// this package provides, and it is not more than that.
//
// # What this package is not
//
// It is not the beginning of a generic SASL framework. internal/sasl contains
// only this directory, and TestSASLFamilyHoldsOnlySCRAM fails if that changes.
// SCRAM-SHA-512 and SCRAM-SHA-256-PLUS are deliberately absent; each needs its
// own decision, recorded in ADR 0056's reopen conditions.
package scram
