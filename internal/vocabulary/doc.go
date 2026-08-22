// Package vocabulary holds the service-neutral evidence vocabulary that more
// than one layer needs.
//
// It is a leaf: it imports internal/domain and nothing else, it contains no
// behaviour, and it exists for one reason. Evidence produced by internal/probe
// and by the composition root is read by internal/diagnosis, and depguard denies
// diagnosis the probe import — correctly, because a probe holds dialers,
// resolvers and live connections, and a rule that could reach one would stop
// being a pure function of a frozen graph.
//
// It is the generic counterpart of internal/service/kafka and
// internal/service/postgres, created on the same terms and for the same reason
// (ADR 0040 section 22, ADR 0042 section 11). Those two hold one service's
// vocabulary each; this one holds the vocabulary that belongs to no service.
//
// # Why a step name has to live somewhere shared
//
// ADR 0042 gives generic transport diagnosis an anchor: a run records the target
// it was asked about, and the sweep it caused is parented to that node. A future
// rule identifies the requested sweep by walking from the anchor through the
// transport chain, which means naming four steps. It cannot import the probes
// that produce three of them, and internal/domain deliberately holds no step
// constants at all — a closed set there would have to enumerate every operation
// of every present and future service in the core, which is the central-registry
// coupling the architecture rejects for finding codes.
//
// So the names live here, the probes alias them, and there is exactly one
// canonical spelling of each.
//
// # Why the L0 anchor sits beside the transport steps
//
// The anchor is not itself a transport observation — it is an L0 input fact. It
// belongs here anyway, because it exists *for* this boundary: it is the root of a
// requested transport chain and is meaningless without one. Splitting it into a
// second leaf would put two halves of one traversal in two packages.
//
// # What must not arrive here
//
// This is a vocabulary, not a package growing in the dark:
//
//   - no service-specific step, attribute key or failure vocabulary. Those live
//     with the service, and move to internal/service/<service> only when a
//     package outside the producing one genuinely reads them.
//   - no behaviour, no identifier encoding, no evidence constructor. Identifier
//     encoding is internal/probe's, because ADR 0019 put it in one place
//     precisely so two producers cannot disagree about it.
//   - no finding code, no severity, no diagnosis policy. ADR 0042 authorizes no
//     finding, and the generic transport finding policy is still open.
//   - no attribute key without a consumer outside the package that produces it.
//     The generic transport keys — dns.answers, tls.verified and the rest — stay
//     where they are produced until a rule genuinely reads one, which is the
//     trigger docs/BACKLOG.md has always named.
package vocabulary
