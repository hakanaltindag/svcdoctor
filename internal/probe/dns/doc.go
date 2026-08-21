// Package dns collects generic DNS facts and normalizes them into evidence.
//
//	Lookup -> observation (producer-local) -> domain.Evidence
//
// It is the first real I/O producer in svcdoctor and the reference
// implementation of the generic transport probe contract. A later probe should
// look like this one; where it cannot, the difference is worth explaining.
//
// # What this package collects
//
// One fact: what the resolver answered for one name, and how long that took.
// Nothing else is a DNS fact.
//
// # What it must never do
//
// It does not decide severity or confidence, create findings, diagnose a root
// cause, or judge a lookup slow. It knows no service: no Kafka, PostgreSQL,
// Redis or MySQL concept may appear here, and no default service port. It
// touches no credential and never calls security.Reveal. It imports neither
// diagnosis nor renderers, which the probe-is-service-agnostic depguard rule
// enforces rather than leaving to review.
//
// Judgement is diagnosis work and runs later, on frozen evidence. This package
// measures now so something else can judge later.
//
// # The evidence contract
//
// One call to Lookup produces exactly one evidence node:
//
//	Layer   L1
//	Step    dns.lookup
//	Subject ENDPOINT, referencing the queried name with no port
//	ID      "dns.lookup/<queried name>"
//
// The subject is an endpoint rather than a target because the evidence is about
// one specific host the run is trying to reach, not about the diagnostic request
// as a whole. It carries no port: at L1 no port has been chosen, and inventing
// one would state something the lookup did not observe. A later layer that does
// know the port uses "host:port". See ADR 0020.
//
// The identifier is derived, not generated: same step and same name mean the
// same identifier, with no clock and no random source involved. See ADR 0019.
//
// # State and failure classification
//
// The mapping is deliberately conservative, because "I could not measure it" and
// "it is broken" are different claims:
//
//	resolver answered with addresses      PASS    -
//	resolver answered with no address     FAIL    DNS_NO_ADDRESS
//	resolver reported not-found           FAIL    DNS_NO_ADDRESS
//	resolver reported a timeout           FAIL    DNS_TIMEOUT
//	any other resolver error              FAIL    DNS_RESOLVER_FAILURE
//	caller's deadline expired             UNKNOWN EXEC_LOCAL_TIMEOUT
//	caller cancelled the run              UNKNOWN EXEC_CANCELLED
//
// The last two rows are the important ones. A deadline that belongs to svcdoctor
// expiring is not evidence that a name cannot be resolved: nothing was learned
// about the target, so the state is UNKNOWN. The distinction survives because the
// observation records the context's own error alongside the resolver's, and the
// standard library does not preserve it: for a caller deadline it returns a
// *net.DNSError whose IsTimeout is true and which does not wrap
// context.DeadlineExceeded, so a probe trusting the error alone would report a
// local budget expiry as a remote DNS timeout.
//
// The context error is consulted only when the lookup actually failed. A lookup
// that completed is a fact, and a deadline expiring immediately afterwards does
// not unmake it.
//
// # NXDOMAIN and NODATA
//
// DNS_NXDOMAIN exists in the domain vocabulary and this package never produces
// it. The standard library reports both "the name does not exist" and "the name
// exists but has no address record" as a *net.DNSError with IsNotFound set, so
// choosing NXDOMAIN would assert non-existence the resolver never evidenced.
//
// DNS_NO_ADDRESS is the weaker claim and says nothing about whether the name
// exists, which is exactly what makes it true in both cases. Its contract is
// explicit about that: "the lookup yielded no usable address".
//
// A resolver that can tell the two apart expresses NODATA as a successful lookup
// with an empty answer set, which normalizes to the same class. DNS_NXDOMAIN
// stays reserved for a resolver that positively evidences non-existence, and a
// producer must not upgrade a not-found answer to it without that evidence.
//
// # Attributes
//
// One attribute, dns.answers, holding the canonical addresses. It is absent
// rather than empty when nothing was resolved, so an absent answer set and an
// empty one are not confused. Everything else a caller might want — how many
// answers, how many of each family — is derivable from it, and a derived
// attribute is a second copy of a fact that can disagree with the first.
//
// Each entry is one address in canonical text form and nothing else. That shape
// is a security requirement, not a preference: structural redaction recognizes an
// identifying attribute value only when it parses as an IP address or a
// host[:port] reference, so an address buried in a sentence would survive into a
// shareable report. See docs/SECURITY.md.
//
// # The Resolver seam
//
// Resolver is the only interface here, and it exists because no test may depend
// on an uncontrolled public service. Testability is a real second implementation,
// which is what the project requires before an interface is justified.
//
// There is deliberately no generic Probe interface. DNS, TCP and TLS take
// different inputs and produce different facts, and a shared shape imposed before
// the transport chain exists would be a guess. Concrete functions first.
//
// # Errors versus evidence
//
// A DNS failure is a diagnostic fact and comes back as evidence, not as a Go
// error. Lookup returns an error only when it was called with input it cannot
// use, or when evidence construction itself fails, both of which are defects in
// the caller or in this package rather than statements about the target.
//
// Raw resolver values never leave this package. The observation holds the
// *net.DNSError and the []netip.Addr; the evidence holds a state, a failure class
// and canonical strings. No error text reaches a report, because an error string
// can carry a resolver address, a search domain or a hostname that structural
// redaction has no way to recognize.
package dns
