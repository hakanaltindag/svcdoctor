package app

import (
	"net/netip"
	"slices"
)

// candidate is one path that completed startup and could be continued.
//
// It carries the concrete address the path reached, which is the only value the
// selector reads. The address comes from the adapter's own result — never from
// an evidence identifier, which is bookkeeping and carries no semantics anything
// may recover (ADR 0019).
type candidate[T any] struct {
	address netip.AddrPort
	result  T

	// authRequired reports that the endpoint demanded credential-based
	// authentication on this path, rather than admitting the connection without
	// asking for anything.
	//
	// It comes from the adapter's own normalized answer, never from the graph.
	authRequired bool
}

// selectPath returns the index of the path that continues past startup, or -1
// when there is nothing to continue.
//
// # Class first, then canonical order
//
// Every startup-successful path could be continued, but they are not equally
// useful to continue, and which one is useful depends on what the run carries.
//
//	wantAuthRequired = true   a credential is configured
//	wantAuthRequired = false  none is
//
// The candidates are partitioned by whether the endpoint demanded credential-based
// authentication on that path, and the preferred class wins outright. The other
// class is used only when the preferred one is empty.
//
// **The reason is product intent, not health.** A `trust` path is not unhealthy
// and a SCRAM path is not healthier — a run that admits a connection without
// asking for anything has told the truth about itself. But an operator who
// supplied a credential asked whether *that credential* works here, and a run
// that continued a path which never asks for one would answer a different
// question and grade it OK. Symmetrically, a run carrying no credential cannot
// exercise a path that demands one, so it prefers the path it can carry to
// ReadyForQuery.
//
// This is candidate selection **before** authentication. It is not a retry and
// not a fallback: exactly one path is continued and at most one credential is
// ever presented, whichever class wins.
//
// # Canonical order here is a tie-break, and that distinction is the decision
//
// ADR 0024 removed "first in canonical address order" from the transport chain
// because it was an invisible IPv4 preference: `netip.Addr.Compare` orders every
// IPv4 address before every IPv6 one, so whichever path was measured first was
// always IPv4, and no test would have caught that changing.
//
// This is not that. By the time this function runs, **every** candidate has
// already been measured through SSLRequest, TLS and Startup, and whatever
// distinguishes them — a different authentication method, a host-based refusal,
// a different server — is already recorded as evidence. Canonical order decides
// only which of several already-measured, already-comparable paths receives the
// one credential a run is allowed to present.
//
// So the ordering is a deterministic tie-break, not a statement that IPv4 is
// preferred, healthier, faster or primary. ADR 0041 section 9 carries the full
// contrast.
//
// # What it must not depend on
//
// Not the order the paths were discovered in, not map iteration, not goroutine
// completion, not latency, not which connection completed first, and not the
// resolver's ordering — which is unavailable anyway, because the DNS probe sorts
// canonically before anything downstream sees an address.
//
// The function is pure and total: same input set, same answer, every time,
// whatever order the slice arrives in.
func selectPath[T any](candidates []candidate[T], wantAuthRequired bool) int {
	if best := canonicalFirst(candidates, wantAuthRequired); best != -1 {
		return best
	}
	// The preferred class is empty. Continue the other one rather than nothing:
	// a path that reached startup is still worth carrying as far as this run
	// can carry it.
	return canonicalFirst(candidates, !wantAuthRequired)
}

// canonicalFirst returns the canonically smallest address within one class, or
// -1 when the class is empty.
func canonicalFirst[T any](candidates []candidate[T], authRequired bool) int {
	return canonicalMinimum(candidates, func(c candidate[T]) bool {
		return c.authRequired == authRequired
	})
}

// canonicalMinimum returns the index of the canonically smallest address among
// the candidates the filter admits, or -1 when it admits none.
//
// It is the one place the comparison is written. Two selectors read it — the
// PostgreSQL class partition above and Kafka's unpartitioned tie-break — and a
// second copy of `Compare` would be a second chance for them to disagree about
// what "canonically smallest" means, which is the drift ADR 0041 section 9's
// determinism argument rests on not happening.
func canonicalMinimum[T any](candidates []candidate[T], include func(candidate[T]) bool) int {
	best := -1
	for i := range candidates {
		if !include(candidates[i]) {
			continue
		}
		if best == -1 || candidates[i].address.Compare(candidates[best].address) < 0 {
			best = i
		}
	}
	return best
}

// sortedAddresses renders a candidate set in canonical order.
//
// It exists for tests and for nothing else: it makes the selector's ordering
// assertable without reaching into the selector, and it is the only place the
// comparison is written twice.
func sortedAddresses[T any](candidates []candidate[T]) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.address)
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return out
}
