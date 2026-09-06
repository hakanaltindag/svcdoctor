package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// The closed vocabularies, each pinned by name.
//
// A name table indexed by an enum drifts the moment a member is inserted in the
// middle, and the failure is silent: every value shifts by one and the report
// starts saying something else. These are the tests that make an insertion a
// compile-time-visible edit rather than a rename of every value after it.

func TestOperationNamesCoverEveryValue(t *testing.T) {
	if got, want := len(operationNames), 4; got != want {
		t.Fatalf("operationNames holds %d entries, want %d", got, want)
	}
	for value, want := range map[Operation]string{
		OperationNone:               "NONE",
		OperationGetService:         "SERVICE_GET",
		OperationListPods:           "POD_LIST",
		OperationListEndpointSlices: "ENDPOINTSLICE_LIST",
	} {
		if got := value.String(); got != want {
			t.Errorf("operation %d renders as %q, want %q", value, got, want)
		}
	}
	if got := Operation(200).String(); !strings.HasPrefix(got, "Operation(") {
		t.Errorf("an out-of-range operation rendered as %q", got)
	}
}

func TestFailureNamesCoverEveryValue(t *testing.T) {
	if got, want := len(failureNames), 12; got != want {
		t.Fatalf("failureNames holds %d entries, want %d", got, want)
	}
	for value := Failure(0); int(value) < len(failureNames); value++ {
		if failureNames[value] == "" {
			t.Errorf("failure %d has no name", value)
		}
	}
	if got := Failure(200).String(); !strings.HasPrefix(got, "Failure(") {
		t.Errorf("an out-of-range failure rendered as %q", got)
	}
}

func TestStopReasonNamesCoverEveryValue(t *testing.T) {
	if got, want := len(stopReasonNames), 7; got != want {
		t.Fatalf("stopReasonNames holds %d entries, want %d", got, want)
	}
	// Every incomplete reason says so in its name, so a consumer reading the
	// vocabulary cannot mistake one for a success.
	for value := StopReason(0); int(value) < len(stopReasonNames); value++ {
		name := stopReasonNames[value]
		if name == "" {
			t.Errorf("stop reason %d has no name", value)
		}
		if value == StopComplete {
			continue
		}
		if !strings.HasPrefix(name, "INCOMPLETE_") {
			t.Errorf("stop reason %q does not say it is incomplete", name)
		}
	}
}

func TestSkipReasonNamesCoverEveryValue(t *testing.T) {
	if got, want := len(skipReasonNames), 6; got != want {
		t.Fatalf("skipReasonNames holds %d entries, want %d", got, want)
	}
	for value := SkipReason(0); int(value) < len(skipReasonNames); value++ {
		if skipReasonNames[value] == "" {
			t.Errorf("skip reason %d has no name", value)
		}
	}
}

// TestOnlyACompleteEnumerationAdmitsAUniversalClaim.
//
// Complete() is deliberately conjunctive. An enumeration that was skipped is not
// complete — nothing was enumerated — and neither is one that stopped at a
// ceiling. Every consumer of a count reads this first.
func TestOnlyACompleteEnumerationAdmitsAUniversalClaim(t *testing.T) {
	if !(Enumeration{Attempted: true, Stop: StopComplete}).Complete() {
		t.Error("an attempted, complete enumeration was reported incomplete")
	}
	if (Enumeration{Attempted: false, Stop: StopComplete}).Complete() {
		t.Error("a skipped enumeration was reported complete.\n\n" +
			"Nothing was enumerated. A skipped list is not an empty one, and only an " +
			"empty *complete* set supports a universal claim.")
	}
	for _, stop := range []StopReason{
		StopPageLimit, StopObjectLimit, StopEndpointLimit,
		StopResourceExpired, StopCancelled, StopRequestFailed,
	} {
		if (Enumeration{Attempted: true, Stop: stop}).Complete() {
			t.Errorf("an enumeration that stopped with %v was reported complete", stop)
		}
	}
}

// TestTheStatusClassificationReadsCodeAndReasonOnly.
//
// # The whole of ADR 0094 section 2.8's structural rule
//
// Two inputs, both from API-contract enumerations. Neither is a message, and
// there is no path by which one could become FailureNotFound or FailureForbidden
// — the two failures Phase 12.1C's findings are built on.
func TestTheStatusClassificationReadsCodeAndReasonOnly(t *testing.T) {
	tests := []struct {
		name   string
		code   int32
		reason metav1.StatusReason
		want   Failure
	}{
		{"401 by reason", 401, metav1.StatusReasonUnauthorized, FailureUnauthorized},
		{"401 by code alone", 401, "", FailureUnauthorized},
		{"403 by reason", 403, metav1.StatusReasonForbidden, FailureForbidden},
		{"403 by code alone", 403, "", FailureForbidden},
		{"404 by reason", 404, metav1.StatusReasonNotFound, FailureNotFound},
		{"404 by code alone", 404, "", FailureNotFound},
		{"410 by reason Expired", 410, metav1.StatusReasonExpired, FailureResourceExpired},
		{"410 by reason Gone", 410, metav1.StatusReasonGone, FailureResourceExpired},
		{"410 by code alone", 410, "", FailureResourceExpired},
		{"500", 500, metav1.StatusReasonInternalError, FailureAPIError},
		{"429", 429, metav1.StatusReasonTooManyRequests, FailureAPIError},
		{"409", 409, metav1.StatusReasonConflict, FailureAPIError},
		{"422", 422, metav1.StatusReasonInvalid, FailureAPIError},
		{"503", 503, metav1.StatusReasonServiceUnavailable, FailureAPIError},
		// A reason this build has never seen must not become a stronger state.
		{"an unknown reason", 418, metav1.StatusReason("TeapotDetected"), FailureAPIError},
		{"an unknown reason with a 404 code", 404, metav1.StatusReason("Whatever"),
			FailureNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyStatus(test.code, test.reason); got != test.want {
				t.Errorf("classifyStatus(%d, %q) = %v, want %v",
					test.code, test.reason, got, test.want)
			}
		})
	}
}

// TestAnArbitraryErrorNeverBecomesAStrongerState.
//
// Everything unrecognized becomes TRANSPORT or API_ERROR, both of which claim
// only that the read did not produce an answer. A message that *says* "not
// found" is still not a NotFound.
func TestAnArbitraryErrorNeverBecomesAStrongerState(t *testing.T) {
	ctx := context.Background()
	for _, err := range []error{
		errors.New("services \"payments-api\" not found"),
		errors.New("forbidden: User cannot list resource"),
		errors.New("Unauthorized"),
		errors.New("410 Gone"),
		errors.New("\x1b[31mNotFound\x1b[0m"),
		fmt.Errorf("wrapped: %w", errors.New("StatusReasonNotFound")),
	} {
		if got := classify(ctx, err); got != FailureTransport {
			t.Errorf("classify(%q) = %v, want TRANSPORT: no error string may become a "+
				"structured state", err, got)
		}
	}
}

// TestTheRunsOwnBudgetIsDistinguishedFromTheServersAnswer.
//
// A local deadline expiring is not proof of remote failure, and the two lead to
// opposite conclusions. The context is asked first, because client-go's wrapping
// of a cancelled request has changed between releases and the context has not.
func TestTheRunsOwnBudgetIsDistinguishedFromTheServersAnswer(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classify(cancelled, context.Canceled); got != FailureCancelled {
		t.Errorf("a cancelled run classified as %v, want CANCELLED", got)
	}

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancelExpired()
	if got := classify(expired, context.DeadlineExceeded); got != FailureTimeout {
		t.Errorf("an expired budget classified as %v, want TIMEOUT", got)
	}

	// A 403 that arrives *while* the context is alive is the server's answer.
	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "services"}, "payments-api", errors.New("nope"))
	if got := classify(context.Background(), forbidden); got != FailureForbidden {
		t.Errorf("a 403 classified as %v, want FORBIDDEN", got)
	}
}

// TestTLSVerificationFailuresAreClassifiedFromTypedErrors.
//
// A CA that does not belong to the cluster the kubeconfig names is the most
// common way a Kubernetes target fails, and reporting it as an unclassified
// transport failure would send an operator to the network when the answer is in
// the file they are holding. The classification is from crypto/x509's typed
// errors and never from a message.
func TestTLSVerificationFailuresAreClassifiedFromTypedErrors(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name string
		err  error
		want Failure
	}{
		{"unknown authority", x509.UnknownAuthorityError{}, FailureTLSUnknownAuthority},
		{"hostname mismatch", x509.HostnameError{Host: "api.internal"},
			FailureTLSHostnameMismatch},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired},
			FailureTLSCertificateExpired},
		{"another certificate problem", x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign},
			FailureTransport},
		{"wrapped", fmt.Errorf("get https://api: %w", x509.UnknownAuthorityError{}),
			FailureTLSUnknownAuthority},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classify(ctx, test.err); got != test.want {
				t.Errorf("classify = %v, want %v", got, test.want)
			}
		})
	}
}

// TestAWrongCertificateAuthorityIsReportedAsOne, end to end.
func TestAWrongCertificateAuthorityIsReportedAsOne(t *testing.T) {
	server := newAPIServer(t)
	// The right server, a certificate authority that signed nothing here.
	//
	// A second httptest server would not do: every httptest TLS server presents
	// the same built-in certificate, so its CA would verify this one and the test
	// would pass while proving nothing. The first version of this test did
	// exactly that.
	unrelated, _ := clientCertificate(t)
	path := kubeconfig{
		server: server.URL(), caPath: writeFile(t, "unrelated-ca.crt", unrelated),
	}.write(t)

	result, err := Acquire(context.Background(), Params{Target: targetFor(path)})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	if got := result.APIAccess.Failure; got != FailureTLSUnknownAuthority {
		t.Errorf("API access failure is %v, want TLS_UNKNOWN_AUTHORITY", got)
	}
	if result.Service.Attempted {
		t.Error("the Service read was recorded as attempted after a handshake failure")
	}
}

// TestClassifyOfNoErrorIsNoFailure keeps the success path honest.
func TestClassifyOfNoErrorIsNoFailure(t *testing.T) {
	if got := classify(context.Background(), nil); got != FailureNone {
		t.Errorf("classify(nil) = %v, want NONE", got)
	}
}

// TestABudgetSetThatCouldNotBoundAnythingIsRefused.
func TestABudgetSetThatCouldNotBoundAnything(t *testing.T) {
	// A negative value is repaired by orDefault, which is the path every caller
	// takes: a partial or nonsensical override becomes the frozen default rather
	// than an unbounded enumeration.
	for _, budgets := range []Budgets{{PageSize: -1}, {MaxPages: -1}, {}} {
		if err := budgets.orDefault().validate(); err != nil {
			t.Errorf("orDefault did not repair %+v: %v", budgets, err)
		}
	}
	// validate is the second line of defence: a caller that bypassed orDefault
	// still cannot obtain an unbounded enumeration.
	if err := (Budgets{PageSize: 0, MaxPages: 1}).validate(); err == nil {
		t.Error("a zero page size was accepted")
	}
	if err := (Budgets{PageSize: 1, MaxPages: 0}).validate(); err == nil {
		t.Error("a zero page ceiling was accepted")
	}
	// A partial override is completed rather than rejected.
	completed := Budgets{MaxPages: 2}.orDefault()
	if completed.PageSize != DefaultBudgets.PageSize {
		t.Errorf("page size is %d, want the default", completed.PageSize)
	}
	if completed.MaxPages != 2 {
		t.Errorf("the override was lost: %+v", completed)
	}
}

// TestAnHTTPStatusWithNoReasonStillClassifies covers a server that answers with a
// bare code, which several proxies and gateways in front of an API server do.
func TestAnHTTPStatusWithNoReasonStillClassifies(t *testing.T) {
	for code, want := range map[int32]Failure{
		http.StatusUnauthorized: FailureUnauthorized,
		http.StatusForbidden:    FailureForbidden,
		http.StatusNotFound:     FailureNotFound,
		http.StatusGone:         FailureResourceExpired,
		http.StatusBadGateway:   FailureAPIError,
	} {
		if got := classifyStatus(code, ""); got != want {
			t.Errorf("classifyStatus(%d, \"\") = %v, want %v", code, got, want)
		}
	}
}
