// Package security provides svcdoctor's security value types.
//
// The package sits at the bottom of the dependency graph and imports only the
// standard library, so every other package may depend on it safely.
//
// # What this package guarantees
//
// Secret and Credential are safe to hand to fmt, to encoding/json, and to error
// wrapping. None of those paths can print plaintext, because the plaintext is
// held in an unexported field and every formatting and serialization method is
// overridden to emit a fixed mask.
//
// Credentials are bound to the endpoint they were created for. There is no way
// to construct an unbound Credential, and no way to read its secret without
// naming the endpoint it is about to be used against.
//
// # What this package does not guarantee
//
// It does not guarantee secure erasure of plaintext from process memory. Go
// cannot provide that: the garbage collector may copy values, strings are
// immutable, and neither swap nor core dumps are under a library's control.
// Secret therefore offers no Zero or Destroy method, because such a method
// would imply a guarantee that does not hold. Lifecycle handling is best-effort
// only, and memory exposure is addressed by process hardening instead. See
// docs/SECURITY.md item 11.
//
// # Reading a secret
//
// Reveal is the single escape hatch that returns plaintext. It is a package
// level function rather than a method so that it does not appear in editor
// completion for a Secret value, and so that every call site is greppable as
// "security.Reveal(". See reveal.go.
package security
