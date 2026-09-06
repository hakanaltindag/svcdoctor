package client

import (
	"context"
	"net/http"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// acquireWithBudgets runs one acquisition under explicit budgets.
//
// Tests supply small ceilings so that exhaustion is reachable without four
// thousand fixtures. TestDefaultBudgetsAreTheFrozenNumbers is what keeps the
// production values honest while these use their own.
func acquireWithBudgets(t *testing.T, server *apiServer, budgets Budgets) Result {
	t.Helper()
	result, err := Acquire(context.Background(), Params{
		Target: targetFor(tokenKubeconfig(t, server)), Budgets: budgets,
	})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	return result
}

// TestDefaultBudgetsAreTheFrozenNumbers states each ceiling on its own.
//
// A single struct comparison would let two numbers swap without the diff saying
// so. These are the values ADR 0094 section 2.5 derived, and changing one is an
// argument rather than a preference.
func TestDefaultBudgetsAreTheFrozenNumbers(t *testing.T) {
	for _, test := range []struct {
		name string
		got  int
		want int
	}{
		{"page size", int(DefaultBudgets.PageSize), 500},
		{"max pages per list", DefaultBudgets.MaxPages, 8},
		{"max Pods", DefaultBudgets.MaxPods, 4000},
		{"max EndpointSlices", DefaultBudgets.MaxSlices, 256},
		{"max endpoints", DefaultBudgets.MaxEndpoints, 10000},
		{"max round trips", MaxRequests, 17},
	} {
		if test.got != test.want {
			t.Errorf("%s is %d, want %d", test.name, test.got, test.want)
		}
	}
	// 1 + 8 + 8. The ceiling is derived from the other two, not chosen beside
	// them, and this is what keeps the three in step.
	if want := 1 + DefaultBudgets.MaxPages*2; MaxRequests != want {
		t.Errorf("the round-trip ceiling %d does not follow from the page ceiling (%d)",
			MaxRequests, want)
	}
}

// TestEveryWayAnEnumerationCanStop is the completeness matrix.
//
// # The one property every row shares
//
// **Only a complete enumeration admits a universal claim**, and every other stop
// reason must leave Complete() false while still reporting what was observed so
// far. A count that survives without its completeness flag is a number a consumer
// would read as a total.
func TestEveryWayAnEnumerationCanStop(t *testing.T) {
	tests := []struct {
		name         string
		budgets      Budgets
		podPages     []scriptedPage
		wantComplete bool
		wantStop     StopReason
		wantObserved int
		wantPages    int
	}{
		{
			name:         "one page, nothing left",
			podPages:     []scriptedPage{{pods: pods(3)}},
			wantComplete: true,
			wantStop:     StopComplete,
			wantObserved: 3,
			wantPages:    1,
		},
		{
			name: "three pages followed to the end",
			podPages: []scriptedPage{
				{pods: pods(2), continueToken: "a"},
				{pods: pods(2), continueToken: "b"},
				{pods: pods(1)},
			},
			wantComplete: true,
			wantStop:     StopComplete,
			wantObserved: 5,
			wantPages:    3,
		},
		{
			name:    "exactly the page ceiling, nothing left",
			budgets: Budgets{MaxPages: 4, MaxPods: 1000},
			podPages: []scriptedPage{
				{pods: pods(1), continueToken: "a"},
				{pods: pods(1), continueToken: "b"},
				{pods: pods(1), continueToken: "c"},
				{pods: pods(1)},
			},
			wantComplete: true,
			wantStop:     StopComplete,
			wantObserved: 4,
			wantPages:    4,
		},
		{
			name:    "the page ceiling with a continue token still outstanding",
			budgets: Budgets{MaxPages: 3, MaxPods: 1000},
			podPages: []scriptedPage{
				{pods: pods(1), continueToken: "a"},
				{pods: pods(1), continueToken: "b"},
				{pods: pods(1), continueToken: "c"},
			},
			wantComplete: false,
			wantStop:     StopPageLimit,
			wantObserved: 3,
			wantPages:    3,
		},
		{
			name:    "the object budget with a continue token still outstanding",
			budgets: Budgets{MaxPages: 8, MaxPods: 2},
			podPages: []scriptedPage{
				{pods: pods(1), continueToken: "a"},
				{pods: pods(1), continueToken: "b"},
			},
			wantComplete: false,
			wantStop:     StopObjectLimit,
			wantObserved: 2,
			wantPages:    2,
		},
		{
			name: "a 410 on the third page",
			podPages: []scriptedPage{
				{pods: pods(1), continueToken: "a"},
				{pods: pods(1), continueToken: "b"},
				{status: &metav1.Status{
					Code: http.StatusGone, Reason: metav1.StatusReasonExpired,
				}},
			},
			wantComplete: false,
			wantStop:     StopResourceExpired,
			wantObserved: 2,
			wantPages:    3,
		},
		{
			name: "a request failure on the second page",
			podPages: []scriptedPage{
				{pods: pods(1), continueToken: "a"},
				{status: &metav1.Status{
					Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
				}},
			},
			wantComplete: false,
			wantStop:     StopRequestFailed,
			wantObserved: 1,
			wantPages:    2,
		},
		{
			name: "a denial on the second page",
			podPages: []scriptedPage{
				{pods: pods(1), continueToken: "a"},
				{status: &metav1.Status{
					Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
				}},
			},
			wantComplete: false,
			wantStop:     StopRequestFailed,
			wantObserved: 1,
			wantPages:    2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAPIServer(t)
			server.service = selectorService("uid-1")
			server.podPages = test.podPages
			server.slicePages = []scriptedPage{{}}

			result := acquireWithBudgets(t, server, test.budgets)

			if got := result.Pods.Complete(); got != test.wantComplete {
				t.Errorf("complete is %v, want %v (%+v)", got, test.wantComplete, result.Pods)
			}
			if got := result.Pods.Stop; got != test.wantStop {
				t.Errorf("stop reason is %v, want %v", got, test.wantStop)
			}
			if got := result.Pods.Observed; got != test.wantObserved {
				t.Errorf("observed %d, want %d", got, test.wantObserved)
			}
			if got := result.Pods.Pages; got != test.wantPages {
				t.Errorf("consumed %d pages, want %d", got, test.wantPages)
			}
			// The whole point: an incomplete enumeration makes the run
			// incomplete, and a complete one does not.
			if got := result.Incomplete(); got == test.wantComplete && !test.wantComplete {
				t.Errorf("incomplete is %v for a %v enumeration", got, test.wantComplete)
			}
			// The EndpointSlice branch is untouched by any of this.
			if !result.Publication.Complete() {
				t.Errorf("the EndpointSlice branch was affected: %+v", result.Publication)
			}
		})
	}
}

// TestA410IsNeverSilentlyRestarted keeps two enumerations from being presented as
// one.
//
// A continue token that expired sampled a moment that has passed. Starting again
// would sample a different one, and the result would carry a single complete flag
// over two disjoint reads.
func TestA410IsNeverSilentlyRestarted(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{
		{pods: pods(2), continueToken: "a"},
		{status: &metav1.Status{Code: http.StatusGone, Reason: metav1.StatusReasonExpired}},
		// Scripted but never reached: consuming it would prove a restart.
		{pods: pods(2)},
	}
	server.slicePages = []scriptedPage{{}}

	result := acquireWithBudgets(t, server, Budgets{})

	if result.Pods.Pages != 2 {
		t.Errorf("the Pod list consumed %d pages; a 410 must end the enumeration and never "+
			"restart it", result.Pods.Pages)
	}
	if result.Pods.Stop != StopResourceExpired {
		t.Errorf("stop reason is %v, want INCOMPLETE_RESOURCE_EXPIRED", result.Pods.Stop)
	}
	if result.Pods.Observed != 2 {
		t.Errorf("observed %d, want 2 — the pages before the expiry and nothing after",
			result.Pods.Observed)
	}
}

// TestAnIncompleteEnumerationIsNeverZero is the rule everything else protects.
//
// # Why this is asserted separately from the matrix above
//
// The matrix proves the flag is right. This proves the **pair** is: an
// enumeration that stopped at a ceiling reports what it saw, and a consumer that
// reads the count without the flag cannot obtain a zero. Reaching a budget must
// not become "no Pods", and it must not become "some Pods" presented as all of
// them either.
func TestAnIncompleteEnumerationIsNeverZero(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	// A first page that fails outright: the shape most likely to be normalized
	// into an empty set by a careless implementation.
	server.podPages = []scriptedPage{{status: &metav1.Status{
		Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
	}}}
	server.slicePages = []scriptedPage{{status: &metav1.Status{
		Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
	}}}

	result := acquireWithBudgets(t, server, Budgets{})

	for _, enumeration := range []Enumeration{result.Pods, result.Publication} {
		if enumeration.Complete() {
			t.Errorf("%s was reported complete after a denied first page", enumeration.Op)
		}
	}
	// Zero observed **and** not complete is the only honest representation of a
	// denied read, and Complete() is what stops it becoming a universal claim.
	if result.Pods.Observed != 0 || result.Pods.Complete() {
		t.Errorf("a denied Pod list produced %+v", result.Pods)
	}
	if result.PublicationFacts.ReadyEndpoints != 0 || result.Publication.Complete() {
		t.Errorf("a denied slice list produced %+v", result.PublicationFacts)
	}
	if !result.Incomplete() {
		t.Error("two denied reads left the run complete")
	}
}

// TestTheEndpointBudgetStopsBeforeCountingPastIt.
//
// The ceiling is checked before an endpoint is counted, so reaching it produces
// an incomplete enumeration rather than a partially consumed page reported as a
// total.
func TestTheEndpointBudgetStopsBeforeCountingPastIt(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{slices: []discoveryv1.EndpointSlice{
		slice("payments-api-a", "uid-1",
			endpoint(ptr(true), nil, nil),
			endpoint(ptr(true), nil, nil),
			endpoint(ptr(true), nil, nil),
		),
	}}}

	result := acquireWithBudgets(t, server, Budgets{MaxEndpoints: 2})

	if result.Publication.Complete() {
		t.Error("an enumeration that hit the endpoint ceiling was reported complete")
	}
	if got := result.Publication.Stop; got != StopEndpointLimit {
		t.Errorf("stop reason is %v, want INCOMPLETE_ENDPOINT_LIMIT", got)
	}
	if got := result.PublicationFacts.Endpoints; got != 2 {
		t.Errorf("counted %d endpoints, want exactly the ceiling of 2", got)
	}
	if !result.Incomplete() {
		t.Error("the run was reported complete after hitting the endpoint ceiling")
	}
}

// TestTheSliceBudgetMakesTheSetIncomplete.
func TestTheSliceBudgetMakesTheSetIncomplete(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{
		{slices: []discoveryv1.EndpointSlice{
			slice("payments-api-a", "uid-1", endpoint(ptr(true), nil, nil)),
			slice("payments-api-b", "uid-1", endpoint(ptr(true), nil, nil)),
		}, continueToken: "more"},
		{slices: []discoveryv1.EndpointSlice{
			slice("payments-api-c", "uid-1", endpoint(ptr(true), nil, nil)),
		}},
	}

	result := acquireWithBudgets(t, server, Budgets{MaxSlices: 2})

	if result.Publication.Complete() {
		t.Error("an enumeration that hit the slice ceiling was reported complete")
	}
	if got := result.Publication.Stop; got != StopObjectLimit {
		t.Errorf("stop reason is %v, want INCOMPLETE_OBJECT_LIMIT", got)
	}
}

// TestCancellationStopsPaginationAndMakesTheSetIncomplete.
//
// A cancelled enumeration is unfinished, never empty, and it must stop
// immediately rather than draining the pages it already asked for.
func TestCancellationStopsPaginationAndMakesTheSetIncomplete(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{
		{pods: pods(1), continueToken: "a"},
		{pods: pods(1), continueToken: "b"},
		{pods: pods(1), continueToken: "c"},
		{pods: pods(1)},
	}
	server.slicePages = []scriptedPage{{}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancelled from inside the handler, as the second request — the first Pod
	// page — is being served. Watching the count from another goroutine races the
	// whole acquisition, which finishes in well under a millisecond against a
	// loopback server; this happens at a known point every time.
	server.beforeRespond = func(request int) {
		if request == 2 {
			cancel()
		}
	}

	result, err := Acquire(ctx, Params{Target: targetFor(tokenKubeconfig(t, server))})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}

	if result.Pods.Complete() {
		t.Error("a cancelled Pod enumeration was reported complete")
	}
	if !result.Incomplete() {
		t.Error("a cancelled run was reported complete")
	}
	// The slice branch was never reached, and says so rather than reporting an
	// empty publication.
	if result.Publication.Complete() {
		t.Errorf("the slice branch was reported complete: %+v", result.Publication)
	}
	// Two requests: the Service GET and the Pod page during which the run was
	// cancelled. A third would mean pagination continued past a dead context.
	if got := server.requestCount(); got > 2 {
		t.Errorf("%d requests were issued; pagination must stop at once on cancellation", got)
	}
}

// TestACancelledRunIssuesNoRequestAtAll covers cancellation before the first GET.
func TestACancelledRunIssuesNoRequestAtAll(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Acquire(ctx, Params{Target: targetFor(tokenKubeconfig(t, server))})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("a cancelled run issued %d requests, want 0", got)
	}
	if result.APIAccess.Attempted {
		t.Error("API access was recorded as attempted")
	}
	if result.APIAccess.Skip != SkipCancelled {
		t.Errorf("API access skip is %v, want CANCELLED", result.APIAccess.Skip)
	}
	if !result.Incomplete() {
		t.Error("a cancelled run was reported complete")
	}
}

// TestPaginationIsBoundedEvenWhenTheServerNeverStops.
//
// A server that returns a continue token forever is the shape a page ceiling
// exists for. Without one, this test would not terminate.
func TestPaginationIsBoundedEvenWhenTheServerNeverStops(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	for i := 0; i < 40; i++ {
		server.podPages = append(server.podPages,
			scriptedPage{pods: pods(1), continueToken: "endless"})
		server.slicePages = append(server.slicePages,
			scriptedPage{slices: []discoveryv1.EndpointSlice{}, continueToken: "endless"})
	}

	result := acquireWithBudgets(t, server, Budgets{})

	if got := result.Pods.Pages; got != DefaultBudgets.MaxPages {
		t.Errorf("the Pod list consumed %d pages, want the ceiling of %d",
			got, DefaultBudgets.MaxPages)
	}
	if got := result.Publication.Pages; got != DefaultBudgets.MaxPages {
		t.Errorf("the slice list consumed %d pages, want the ceiling of %d",
			got, DefaultBudgets.MaxPages)
	}
	if got := result.Requests; got > MaxRequests {
		t.Errorf("%d round trips exceeds the frozen ceiling of %d", got, MaxRequests)
	}
	if got := result.Requests; got != MaxRequests {
		t.Errorf("the worst case issued %d round trips, want exactly %d — the ceiling is "+
			"1 + 8 + 8 and this is the run that reaches it", got, MaxRequests)
	}
	for _, enumeration := range []Enumeration{result.Pods, result.Publication} {
		if enumeration.Complete() {
			t.Errorf("%s was reported complete against an endless server", enumeration.Op)
		}
	}
}

// TestAPageCeilingReachedWithNothingLeftIsNotATruncation.
//
// Finishing at a ceiling is not the same as being cut off by one, and only an
// outstanding continue token distinguishes them.
func TestAPageCeilingReachedWithNothingLeftIsNotATruncation(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{
		{pods: pods(2), continueToken: "a"},
		{pods: pods(2)},
	}
	server.slicePages = []scriptedPage{{}}

	result := acquireWithBudgets(t, server, Budgets{MaxPages: 2, MaxPods: 4})

	if !result.Pods.Complete() {
		t.Errorf("an enumeration that finished exactly at its ceilings was reported "+
			"incomplete: %+v", result.Pods)
	}
	if result.Incomplete() {
		t.Error("the run was reported incomplete")
	}
}

// TestPaginationIssuesNoRequestOnADeadContext.
//
// # Why this drives paginate directly
//
// The end-to-end cancellation test above proves the *outcome* — an incomplete
// set — but not the mechanism, because a request issued on a dead context fails
// at the transport and produces the same outcome by a different route. Planting
// the removal of the pre-request check showed exactly that: the mutation
// survived.
//
// What the check buys is that **no further round trip is attempted at all**,
// which matters because svcdoctor's budget ending is not a reason to add load to
// a control plane. Counting fetch calls is the only way to see it.
func TestPaginationIssuesNoRequestOnADeadContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetches := 0
	requests := 0
	result := paginate(
		ctx, OperationListPods, DefaultBudgets, "app=x", DefaultBudgets.MaxPods,
		func(context.Context, metav1.ListOptions) (page[int], error) {
			fetches++
			return page[int]{}, nil
		},
		func(items []int) (int, StopReason) { return len(items), StopComplete },
		&requests,
	)

	if fetches != 0 {
		t.Errorf("%d requests were issued on a dead context, want 0", fetches)
	}
	if requests != 0 {
		t.Errorf("the round-trip counter moved to %d, want 0", requests)
	}
	if result.Complete() {
		t.Error("a cancelled enumeration was reported complete")
	}
	if result.Stop != StopCancelled {
		t.Errorf("stop reason is %v, want INCOMPLETE_CANCELLED", result.Stop)
	}
	if result.Failure != FailureCancelled {
		t.Errorf("failure is %v, want CANCELLED", result.Failure)
	}
}

// TestPaginationStopsBetweenPagesWhenTheBudgetEnds.
//
// The same property one page in: a context that dies after a successful page must
// stop the loop before the next fetch, rather than issuing one that fails.
func TestPaginationStopsBetweenPagesWhenTheBudgetEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fetches := 0
	requests := 0
	result := paginate(
		ctx, OperationListPods, DefaultBudgets, "app=x", DefaultBudgets.MaxPods,
		func(context.Context, metav1.ListOptions) (page[int], error) {
			fetches++
			// The budget ends as this page is handed back, which is the shape a
			// deadline expiring mid-run actually has.
			cancel()
			return page[int]{items: []int{1, 2}, next: "more"}, nil
		},
		func(items []int) (int, StopReason) { return len(items), StopComplete },
		&requests,
	)

	if fetches != 1 {
		t.Errorf("%d requests were issued, want exactly 1: the loop must stop before the "+
			"next page rather than issue one that fails", fetches)
	}
	if result.Complete() {
		t.Error("a cancelled enumeration was reported complete")
	}
	// The page that did arrive is still counted — it was measured — and it is
	// still not a total.
	if result.Observed != 2 {
		t.Errorf("observed %d, want 2", result.Observed)
	}
}
