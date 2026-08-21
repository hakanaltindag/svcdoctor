// Package domain holds svcdoctor's service-neutral diagnostic vocabulary.
//
// These are values and semantics, not collectors. Nothing here resolves a name,
// opens a socket, reads a file, inspects the environment, or reads a clock.
// Collection belongs to the probe, adapter, and platform layers; this package
// only describes what they produce.
//
// The package is service neutral. No Kafka, PostgreSQL, Redis, RabbitMQ, MySQL,
// or Elasticsearch concept may appear here. Service-specific detail is carried
// as normalized attributes, never as new types or branches in this package.
//
// # Zero values
//
// The three enumerations deliberately differ in what their zero value means,
// because the safe reading of "unset" differs for each:
//
//   - State zero is StateUnknown, which is valid. "Could not be determined" is
//     an honest reading of an unset result, and the report schema locks exactly
//     five states, so adding a sixth sentinel would invent a state.
//   - Layer zero is LayerUnspecified, which is invalid. L0 is a real layer, so
//     if zero meant L0 a forgotten layer would silently claim to be
//     config-layer evidence. There is no safe layer to default to.
//   - FailureClass zero is FailureNone, which is valid. The report schema states
//     that failureClass is meaningless on a PASS node, so "absent" is a
//     legitimate value rather than an error.
//
// # Why there is no domain.Observation
//
// The architecture chain is
// "raw result -> Observation -> normalized Evidence -> Diagnosis -> Finding",
// and an observation is a real stage. It is deliberately not a type in this
// package, and it should not be added here later.
//
// An observation is producer-shaped by definition. What a DNS lookup produces,
// a list of addresses with an RCODE and a latency, has nothing structurally in
// common with what a protocol capability exchange produces. A single generic
// observation type could therefore only be one of two things, and both are
// excluded:
//
//   - a duplicate of Evidence, carrying the same layer, step, state, and
//     attributes, in which case it adds a stage without adding a boundary
//   - a container of arbitrary values, which ADR 0010 forbids in the canonical
//     model precisely because it defeats schema stability, deterministic
//     serialization, and structural redaction at once
//
// The stage is real but it belongs to the producer. It materializes as concrete
// typed structs in the packages that create facts, such as an observation type
// inside a DNS probe or a Kafka adapter, each shaped like the thing it observed.
// Those types normalize into Evidence at their own boundary and never cross it,
// which is exactly what "normalization happens at the probe or adapter boundary"
// means in docs/ARCHITECTURE.md.
//
// # What the evidence graph is not responsible for
//
// Graph and GraphBuilder store structure. Several things that look adjacent are
// deliberately not theirs, and must not be moved into them later:
//
//   - Endpoint deduplication. Deciding that two endpoints denote the same
//     execution target requires knowing what an endpoint is, and the answer
//     differs by service and by vantage point. The builder deduplicates
//     identifiers and edges, never subjects.
//   - Topology recursion depth and visited-endpoint tracking. Cycle detection
//     inside the builder is graph integrity; "do not probe this endpoint again"
//     is execution policy, and the two must not be conflated.
//   - Execution scheduling, retries, timeouts, concurrency, and which layer runs
//     next.
//   - Short-circuit decisions. The builder records that a step was skipped and
//     what blocked it. Deciding that a failed DNS lookup should stop a TCP
//     attempt happens in orchestration.
//
// # Why there is no Origin
//
// An origin field distinguishing a user-supplied subject from a discovered one
// was considered and deferred twice.
//
// It has no consumer, because topology discovery does not exist yet. Adding it
// now would introduce a second place that records how a subject entered the run,
// alongside the graph structure itself, and there is no implementation to show
// which of the two should be authoritative or whether they can disagree.
//
// Whether explicit provenance is necessary is a question only a real topology
// implementation can answer. Until then the field stays out. This is a deferral,
// not a rejection: revisit it when topology orchestration exists. See ADR 0013.
//
// # Invalid values
//
// Every enumeration exposes Valid. String never fails and renders an
// out-of-range value in the Go convention, for example "Layer(42)", so that a
// corrupt value is visible rather than disguised as a legitimate one.
// MarshalJSON refuses an invalid value with ErrInvalidValue, because JSON is the
// canonical report representation and must not carry a value that no consumer
// can interpret. String is for humans and must never fail; JSON is a contract
// and must not encode nonsense.
package domain
