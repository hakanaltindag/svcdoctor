package client

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// classify turns a client-go error into svcdoctor's own closed vocabulary.
//
// # It reads structure and never text
//
// The inputs are, in order: the run's own context error, a typed crypto/x509
// verification error, the HTTP status code and metav1.StatusReason carried by a
// *apierrors.StatusError, and nothing else. **Status.Message,
// Status.details.causes[].message and every condition message are never read**,
// so a hostile status string carrying ANSI, CRLF, a token-shaped value or a
// filesystem path has no path into a Failure, into evidence, or into a report.
// That is structural, not an escaping exercise (ADR 0094 section 2.8).
//
// # An unrecognized error never produces a stronger state
//
// Everything this function does not recognize becomes FailureAPIError or
// FailureTransport, both of which claim only that the read did not produce an
// answer. There is no path by which a novel API reason or an arbitrary error
// string can become FailureNotFound or FailureForbidden — the two failures a
// Phase 12.1C finding will be built on.
//
// ctx is the run's context, consulted first: a request that failed *because* the
// budget ended is svcdoctor's own limit and not the API server's answer, and the
// two lead to opposite conclusions.
func classify(ctx context.Context, err error) Failure {
	if err == nil {
		return FailureNone
	}

	// The run's own budget comes first, and it is asked of the context rather
	// than of the error. client-go wraps a cancelled request in several layers
	// and the wrapping has changed between releases; the context has not.
	switch {
	case errors.Is(err, context.DeadlineExceeded), ctx.Err() == context.DeadlineExceeded:
		return FailureTimeout
	case errors.Is(err, context.Canceled), ctx.Err() == context.Canceled:
		return FailureCancelled
	}

	// TLS verification, from typed errors rather than from a message. A CA that
	// does not belong to the cluster the kubeconfig names is the most common way
	// a Kubernetes target fails, and reporting it as an unclassified transport
	// failure would send an operator to the network when the answer is in the
	// file they are holding.
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknownAuthority):
		return FailureTLSUnknownAuthority
	case errors.As(err, &hostname):
		return FailureTLSHostnameMismatch
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return FailureTLSCertificateExpired
		}
		return FailureTransport
	}

	var status *apierrors.StatusError
	if !errors.As(err, &status) {
		// No API status was obtained at all, so the API server never answered.
		return FailureTransport
	}
	return classifyStatus(status.ErrStatus.Code, status.ErrStatus.Reason)
}

// classifyStatus maps an HTTP status code and a StatusReason onto a Failure.
//
// Both are consulted because neither alone is sufficient: an API server may
// answer 403 with an empty Reason, and `Expired` arrives with a 410 that has no
// other distinguishing code. Where the two disagree the Reason wins, because it
// is the API's own enumeration and the code is a transport-level summary of it.
//
// The mapping is exhaustive over what svcdoctor distinguishes and closed over
// everything else. It is a separate function from classify so that a test can
// drive every reachable status without constructing a transport error.
func classifyStatus(code int32, reason metav1.StatusReason) Failure {
	switch reason {
	case metav1.StatusReasonUnauthorized:
		return FailureUnauthorized
	case metav1.StatusReasonForbidden:
		return FailureForbidden
	case metav1.StatusReasonNotFound:
		return FailureNotFound
	case metav1.StatusReasonExpired, metav1.StatusReasonGone:
		return FailureResourceExpired
	}

	switch code {
	case http.StatusUnauthorized:
		return FailureUnauthorized
	case http.StatusForbidden:
		return FailureForbidden
	case http.StatusNotFound:
		return FailureNotFound
	case http.StatusGone:
		return FailureResourceExpired
	}
	return FailureAPIError
}
