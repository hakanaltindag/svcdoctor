package client

import "fmt"

// Budgets bound one acquisition.
//
// # Every ceiling produces the same outcome, and it is never emptiness
//
// Reaching any of these makes the affected set **INCOMPLETE**. None of them
// produces a truncated set presented as a total, and none of them may become
// "no Pods" or "no ready endpoints" — that is the distinction the whole
// completeness model exists to preserve (ADR 0094 section 2.5).
//
// # Where the numbers come from
//
// They are derived rather than chosen, and the derivations are recorded so that
// changing one is an argument rather than a preference:
//
//   - PageSize 500: one round trip covers the overwhelming majority of real
//     namespaces while keeping a single response small enough to hold and
//     normalize.
//   - MaxPages 8: with PageSize 500 this bounds each list at 4,000 objects and
//     at 8 round trips.
//   - MaxPods 4,000: 8 × 500. Far above any single Service's realistic backend
//     count, and a namespace larger than that is one where a universal claim
//     should be withheld anyway.
//   - MaxSlices 256: at the API ceiling of 1,000 endpoints per slice this admits
//     256,000 endpoints; at the controller default of 100 it admits 25,600.
//     Dual-stack doubles the slice count, so the ceiling must not be small.
//   - MaxEndpoints 10,000: the point at which enumeration stops being an
//     incident measurement.
//   - The resulting round-trip ceiling is 1 + 8 + 8 = **17**.
//
// # What is not bounded, and it is recorded rather than claimed away
//
// `limit` bounds the **number of objects** in a page, not the response's **byte
// size**: a single Pod carrying large annotations can be hundreds of kilobytes,
// and 500 of them is not a byte bound. client-go's typed clients expose no
// per-response body ceiling, so obtaining one would mean replacing the
// transport. First scope bounds objects, pages and round trips; the byte
// exposure is bounded in practice by the page size and by svcdoctor retaining
// sixteen normalized values and discarding every decoded object immediately.
// See docs/SECURITY.md.
type Budgets struct {
	// PageSize is the `limit` sent with every list request.
	PageSize int64

	// MaxPages is how many responses one list may consume.
	MaxPages int

	// MaxPods is the object ceiling for the Pod enumeration.
	MaxPods int

	// MaxSlices is the object ceiling for the EndpointSlice enumeration.
	MaxSlices int

	// MaxEndpoints is the aggregate ceiling on endpoints normalized across every
	// admitted slice.
	MaxEndpoints int
}

// DefaultBudgets are the values ADR 0094 section 2.5 froze.
//
// TestDefaultBudgetsAreTheFrozenNumbers asserts each one individually, so a
// change here appears in a diff as a number rather than as a behaviour nobody
// noticed.
var DefaultBudgets = Budgets{
	PageSize:     500,
	MaxPages:     8,
	MaxPods:      4000,
	MaxSlices:    256,
	MaxEndpoints: 10000,
}

// MaxRequests is the frozen ceiling on API round trips for one acquisition.
//
// One Service GET, eight Pod pages, eight EndpointSlice pages. It is asserted
// against a request-counting server rather than argued, because the only way an
// extra round trip appears is a library doing something on svcdoctor's behalf —
// a discovery call, a version negotiation, a redirect — and arithmetic cannot
// see any of those.
const MaxRequests = 17

// orDefault fills in the frozen values for any field a caller left zero.
//
// Tests supply small budgets so that exhaustion is reachable without four
// thousand fixtures; production supplies none and gets the frozen set. A partial
// override is completed rather than rejected, so a test that cares about pages
// does not have to restate the endpoint ceiling.
func (b Budgets) orDefault() Budgets {
	if b.PageSize <= 0 {
		b.PageSize = DefaultBudgets.PageSize
	}
	if b.MaxPages <= 0 {
		b.MaxPages = DefaultBudgets.MaxPages
	}
	if b.MaxPods <= 0 {
		b.MaxPods = DefaultBudgets.MaxPods
	}
	if b.MaxSlices <= 0 {
		b.MaxSlices = DefaultBudgets.MaxSlices
	}
	if b.MaxEndpoints <= 0 {
		b.MaxEndpoints = DefaultBudgets.MaxEndpoints
	}
	return b
}

// validate refuses a budget set that could not bound anything.
func (b Budgets) validate() error {
	switch {
	case b.PageSize <= 0:
		return fmt.Errorf("%w: the page size must be positive", ErrTarget)
	case b.MaxPages <= 0:
		return fmt.Errorf("%w: the page ceiling must be positive", ErrTarget)
	}
	return nil
}
