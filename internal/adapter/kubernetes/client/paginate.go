package client

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// page is one list response, reduced to what pagination needs.
type page[T any] struct {
	items []T
	next  string
}

// consumer normalizes one page and reports what it did.
//
// It returns how many objects it accounted for and, when a sub-budget of its own
// stopped it, the reason. Returning StopComplete means "carry on"; anything else
// ends the enumeration immediately with that reason.
//
// It exists so that the endpoint ceiling — which is about the *contents* of a
// slice rather than about how many slices there are — can stop pagination
// without paginate knowing what an endpoint is.
type consumer[T any] func(items []T) (accounted int, stop StopReason)

// paginate performs one bounded, explicitly paginated list.
//
// # The whole of the completeness contract lives here
//
//	every list sends an explicit limit
//	a returned continue token is followed
//	pages accumulate only until an object or page ceiling is reached
//	a remaining continue token at a ceiling makes the set INCOMPLETE
//	a 410 makes the set INCOMPLETE and is never silently restarted
//	a cancellation makes the set INCOMPLETE
//	a failed request makes the set INCOMPLETE
//
// **There is no retry of any kind**, and no restart. A 410 means the token
// sampled a moment that has passed, and starting again would sample a different
// moment and present the two as one enumeration. A 429 or a 5xx ends the read
// for the same reason a retry loop is refused everywhere else in svcdoctor: it
// turns one bounded diagnosis into a small monitoring loop.
//
// # Cross-page consistency is not assumed
//
// The Kubernetes API's own documentation is explicit that a paginated list is
// **not** a consistent snapshot unless a resourceVersion is pinned, and that a
// continue token may expire. svcdoctor pins nothing and relies on
// **completeness** instead — every page followed, no token remaining, within
// budget — which is a weaker claim that is correct whatever the consistency
// guarantee turns out to be. Completeness proves complete traversal of one list
// operation, and it proves nothing at all across the three operations: the
// Service GET, the Pod list and the EndpointSlice list are three separate
// moments and no claim spans them (ADR 0094 section 9.4).
//
// requests is incremented once per issued round trip, so the caller can assert
// the frozen ceiling against a counting server rather than against arithmetic.
func paginate[T any](
	ctx context.Context,
	op Operation,
	budgets Budgets,
	selector string,
	maxObjects int,
	fetch func(context.Context, metav1.ListOptions) (page[T], error),
	consume consumer[T],
	requests *int,
) Enumeration {
	started := time.Now()
	out := Enumeration{Op: op, Attempted: true, StartedAt: started, Stop: StopComplete}

	options := metav1.ListOptions{Limit: budgets.PageSize, LabelSelector: selector}

	for out.Pages < budgets.MaxPages {
		// Checked before each request rather than only after, so a run whose
		// budget ended between two pages issues no further round trip.
		if err := ctx.Err(); err != nil {
			out.Stop = StopCancelled
			out.Failure = classify(ctx, err)
			out.Elapsed = time.Since(started)
			return out
		}

		result, err := fetch(ctx, options)
		*requests++
		out.Pages++
		if err != nil {
			out.Failure = classify(ctx, err)
			switch out.Failure {
			case FailureResourceExpired:
				out.Stop = StopResourceExpired
			case FailureCancelled, FailureTimeout:
				out.Stop = StopCancelled
			default:
				out.Stop = StopRequestFailed
			}
			out.Elapsed = time.Since(started)
			return out
		}

		accounted, stop := consume(result.items)
		out.Observed += accounted
		if stop != StopComplete {
			out.Stop = stop
			out.Elapsed = time.Since(started)
			return out
		}

		// A ceiling reached with nothing left to fetch is not a truncation: the
		// enumeration finished and happened to finish at the ceiling. Only an
		// outstanding continue token turns a ceiling into an incomplete set.
		if result.next == "" {
			out.Elapsed = time.Since(started)
			return out
		}
		if maxObjects > 0 && out.Observed >= maxObjects {
			out.Stop = StopObjectLimit
			out.Elapsed = time.Since(started)
			return out
		}
		options.Continue = result.next
	}

	// The loop exited on the page ceiling with a token still outstanding, which
	// is the one remaining way to leave a set incomplete.
	out.Stop = StopPageLimit
	out.Elapsed = time.Since(started)
	return out
}

// skippedEnumeration records a list that was deliberately not issued.
//
// **It is not an empty set**, and the distinction is load-bearing: an empty
// complete set supports a universal claim and a skipped one supports none.
// Complete() returns false for it by construction, because Attempted is false.
func skippedEnumeration(op Operation, reason SkipReason) Enumeration {
	return Enumeration{Op: op, Attempted: false, Skip: reason}
}
