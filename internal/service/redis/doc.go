// Package redis holds the Redis and Valkey vocabulary that more than one layer
// needs.
//
// It is a leaf: it imports internal/domain and nothing else, it contains no
// behaviour, and it exists for one reason. Evidence produced by
// internal/adapter/redis is read by internal/diagnosis/redis and by
// internal/render/terminal, and depguard denies both the adapter import —
// correctly, because an adapter holds protocol machinery, live connections and
// credentials, and a rule that could reach it could stop being a pure function
// of a frozen graph.
//
// It is the exact counterpart of internal/service/kafka and internal/service/
// postgres, and was created on the same terms.
//
// # One vocabulary for two implementations
//
// There is no `internal/service/valkey`. ADR 0066 section 6 freezes one adapter
// and one CLI command for both, because every command in the frozen journey
// behaves identically on each. The implementation an endpoint reports is an
// *attribute* in this package rather than a fork of it, which is what makes
// "svcdoctor said redis because the operator typed redis" impossible to write.
//
// # What is here, and why each constant earned its place
//
// Three step names, because a rule has to name the node it anchors at. Seven
// attribute keys, because something outside the adapter genuinely reads each:
//
//   - AttrMode is the Sentinel guard's entire predicate, and the renderer's
//     "topology not measured" line.
//   - AttrRole, AttrServer, AttrServerVersion and AttrProto are rendered as
//     observations. No rule reads them, and a test enforces that no rule starts.
//   - AttrErrorPrefix carries what an endpoint named when it refused, so a rule
//     can state that without reading a byte the peer chose.
//   - AttrAuthRequired distinguishes an endpoint that demands a credential from
//     one that does not, which is what a report has to show separately from
//     whether a credential was presented.
//
// Everything else a rule needs is already service-neutral domain data: the
// subject, the state, the failure class, the layer and the edges.
//
// # What must not arrive here
//
//   - No wire type, no RESP frame, no parser, no error-prefix table beyond the
//     key that names one. Those stay in internal/adapter/redis/wire, behind the
//     boundary ADR 0063 draws.
//   - No connection ownership type and no session type. Redis has no session,
//     and anything holding a socket belongs to the adapter.
//   - No command name. The allowlist is the wire package's, enforced there.
//   - No key for a fact only the adapter reads.
//   - No expected-state vocabulary of any kind: no expected role, no expected
//     implementation, no expected mode. BASIC has no expectation contract, and a
//     constant here would be the first half of one.
package redis
