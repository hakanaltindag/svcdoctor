// Package kafka holds the Kafka vocabulary that more than one layer needs.
//
// It is a leaf: it imports internal/domain and nothing else, it contains no
// behaviour, and it exists for one reason. Evidence produced by
// internal/adapter/kafka is read by internal/diagnosis/kafka, and depguard
// denies diagnosis the adapter import — correctly, because an adapter holds
// protocol machinery, live connections and credentials, and a rule that could
// reach it could stop being a pure function of a frozen graph.
//
// The shared surface is three constants. A rule that anchors at a Kafka
// advertisement has to name the step it is looking for and the step that
// carried it; everything else it reads is already service-neutral domain data —
// the subject, the state, the failure class, the layer and the edges. See
// ADR 0034 section 19, which authorized this package and fixed its contents.
//
// # What must not arrive here
//
// This is a vocabulary, not a service package growing in the dark:
//
//   - no interface, no registry, no dispatcher and no Adapter type. Service
//     selection happens by explicit registration at a composition root that does
//     not exist yet (ADR 0009).
//   - no protocol logic, no wire types and no runtime types. Those stay in the
//     adapter, behind the boundary ADR 0025 draws.
//   - no second copy of a fact the evidence already carries. The advertised host
//     and port are on the advertisement's subject, so their attribute keys stay
//     in the adapter rather than being moved here to be read a second way.
//   - no attribute key whose only consumer is the adapter itself.
//
// A constant earns a place here when a package outside internal/adapter/kafka
// genuinely reads it. Until then it stays where it is produced.
package kafka
