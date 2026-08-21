// Package transport runs the generic transport chain for one endpoint:
//
//	DNS -> TCP for every resolved address -> TLS where the caller asked for it
//
// It is the first orchestration in the repository. Probes collect facts and know
// nothing about each other or about the graph; this package decides what runs
// next, records the relationships, and owns the connections that survive.
//
// It orchestrates transport and nothing else. It reaches no conclusion about
// whether the endpoint is healthy, assigns no severity, and produces no finding:
// those need policy, and policy is diagnosis work over frozen evidence.
//
// # Every resolved address is attempted
//
// A production client stops at the first address that works. svcdoctor does not,
// because the addresses it does not try are exactly the ones that hide the
// problem: one broken address family, one host behind a different firewall rule,
// one member of a load-balanced set that is down. Stopping early would make the
// report depend on which address happened to be listed first.
//
// So the chain sweeps the whole canonical address set and records one TCP node —
// and, where TLS was requested, one TLS node — per address. Partial success stays
// visible as partial success; nothing is aggregated.
//
// # Every completed path is handed back, and the chain chooses none of them
//
// Sweeping every address can produce several usable connections. The chain keeps
// them all and picks no favourite, because there is no transport-level reason to
// prefer one working path over another: any rule it applied would be a client
// policy wearing a mechanism's clothes. Ordering by canonical address, for
// instance, would quietly make IPv4 the continuation whenever both families
// work, since that ordering puts every IPv4 address first.
//
// Which working path a protocol should speak over is a decision for the layer
// that knows what it is about to say. This one does not, so it does not decide.
//
// A caller that wanted only the evidence closes the Result and every connection
// goes with it. A caller that wants one takes it and closes the rest — or closes
// the Result, which does that for it.
//
// Ownership never becomes ambiguous. A connection belongs to the TCP result, then
// to the TLS handshake, then to this chain's Result, then to whoever calls
// TakeConn on its Continuation. At every instant exactly one value is responsible
// for closing it, and the connection handed on is the one the evidence describes:
// nothing is redialed.
//
// # Execution is sequential
//
// Addresses are attempted one at a time, in the canonical order the DNS probe
// produced. Concurrency would buy latency, which is not what a diagnostic tool is
// optimizing, and it would make the evidence — and the order of the returned
// continuations — depend on which handshake finished first. See ADR 0024.
//
// # The graph is the caller's
//
// The chain writes into a domain.GraphBuilder the caller owns and never freezes
// it. One run of one endpoint is not one report: a topology sweep will record
// many endpoints into one graph, and only the caller knows when the run is over.
//
//	DNS
//	 ├── TCP(10.0.0.1)  ── TLS(10.0.0.1)
//	 ├── TCP(10.0.0.2)  ── TLS(10.0.0.2)   SKIPPED, blocked by TCP(10.0.0.2)
//	 └── TCP(2001:db8::1) ── TLS(2001:db8::1)
//
// A parent edge here means derivation: the TCP attempt exists because the lookup
// produced that address. It is not provenance, and nothing may read `Origin` out
// of the shape of this graph (ADR 0013).
//
// # What is not recorded
//
// When a lookup yields no address there are no TCP or TLS nodes, because there is
// no address to name and a subject must name what its layer touched. The failed
// DNS node is the record. See ADR 0024 and docs/ARCHITECTURE.md section 12.
package transport
