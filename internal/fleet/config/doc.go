// Package config decodes and validates a multi-target configuration file.
//
// It is the generic half of ADR 0071: it owns the bytes, the YAML syntax, the
// configuration version, the target envelope, the bounds, identity uniqueness,
// dispatch to a registered service, and the structural shape of a credential
// reference. It owns nothing about any protocol.
//
// # It is the only package that may import the YAML library
//
// ADR 0071 section 3.3. A dependency that exactly one package can name cannot
// spread by convenience, which is the same containment ADR 0025 gives the Kafka
// protocol library. ServiceNode is what makes that possible without taking
// decoding away from services: a service receives an opaque subtree and decodes
// it into its own type, so a fifth service adds no importer of the dependency.
//
// # It cannot construct a secret
//
// This package does not import internal/security. That is ADR 0072 section 6 as
// a compile-time property rather than a convention — the parser does not decline
// to build a secret, it has no type to build one with. A Reference has two
// string fields and both are names.
//
// # What it does not do
//
//	no network I/O          nothing is resolved, dialled or handshaken
//	no environment reads    os.Getenv is absent, and a guard proves it
//	no credential reads     a `file:` reference is a path, never opened here
//	no protocol semantics   a service validates its own configuration
//	no execution            Phase 9.1B owns the runner
//
// The only file it opens is the configuration itself.
//
// # Validation is all-or-nothing
//
// Load returns a whole validated Config or an error, never a partial one.
// ADR 0074 section 9 requires that any configuration error means zero targets
// are dialled, and the alternative — validating lazily — means an operator
// discovers target 18 is malformed after 17 targets have been authenticated
// against, each of which is logged, counted, and in directory-backed deployments
// a step toward lockout.
//
// # Order is preserved and never derived
//
// Targets live in a slice from decode onward. Nothing here sorts them and
// nothing iterates a map to produce them, which is what makes ADR 0073
// section 6's declared-order guarantee structural rather than a rule someone
// follows.
package config
