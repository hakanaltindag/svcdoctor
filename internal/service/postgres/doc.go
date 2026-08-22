// Package postgres holds the PostgreSQL vocabulary that more than one layer
// needs.
//
// It is a leaf: it imports internal/domain and nothing else, it contains no
// behaviour, and it exists for one reason. Evidence produced by
// internal/adapter/postgres is read by internal/diagnosis/postgres, and depguard
// denies diagnosis the adapter import — correctly, because an adapter holds
// protocol machinery, live connections and credentials, and a rule that could
// reach it could stop being a pure function of a frozen graph.
//
// It is the exact counterpart of internal/service/kafka and was created on the
// same terms, authorized by ADR 0040 section 22.
//
// # What is here, and why each constant earned its place
//
// Four step names, because a rule has to name the node it anchors at and the
// nodes it walks to. Four attribute keys, because a rule genuinely reads them:
//
//   - AttrSSLOffered distinguishes "the endpoint declined" from "svcdoctor never
//     found out", which is the whole predicate of the TLS finding.
//   - AttrAuthMethod carries the trust path, where a session's parent is the
//     startup node rather than an authentication node.
//   - AttrSQLState and AttrErrorIsNative are rendered verbatim in a floor
//     finding's detail, as observations and never as conclusions.
//
// Everything else a rule needs is already service-neutral domain data: the
// subject, the state, the failure class, the layer and the edges.
//
// # What must not arrive here
//
// This is a vocabulary, not a service package growing in the dark:
//
//   - no wire type, no protocol parser, no frame, no SQLSTATE table. Those stay
//     in the adapter, behind the boundary ADR 0036 draws, and a SQLSTATE is
//     classified per step by the adapter for the reason ADR 0039 section 7.1
//     gives.
//   - no authentication state, no connection ownership type, no Session,
//     StartupResult or AuthenticatedSession. Those carry a live socket.
//   - no interface, registry, dispatcher or Adapter type. Service selection
//     happens by explicit registration at a composition root that does not exist
//     yet (ADR 0009).
//   - no second copy of a fact the evidence already carries.
//   - no attribute key whose only consumer is the adapter itself. postgres.role,
//     postgres.database, postgres.tls.plan, postgres.sasl_mechanism,
//     postgres.scram_iterations, postgres.protocol_version,
//     postgres.error_severity and every session parameter stay where they are
//     produced, because no authorized rule reads them.
//
// A constant earns a place here when a package outside internal/adapter/postgres
// genuinely reads it. Until then it stays where it is produced.
package postgres
