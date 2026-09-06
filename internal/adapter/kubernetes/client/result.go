package client

import (
	"strconv"
	"time"
)

// Operation is the closed vocabulary of Kubernetes API operations svcdoctor
// performs.
//
// Exactly three, and no fourth is reachable: there is no discovery request, no
// version negotiation, no SelfSubjectAccessReview, no watch, no re-GET and no
// read of a namespace, a node, an event, a log, a Secret or a ConfigMap.
//
// It exists as an enum rather than a string because Phase 12.1C's
// KUBERNETES_API_ACCESS_DENIED has to name *which* read was denied, and naming
// it from a closed map is ADR 0069 section 6's division applied again: the class
// explains the kind of break, the sentinel explains which one. A raw HTTP method
// and path would put a URL — and with it the API server's identity — into
// canonical data.
type Operation uint8

const (
	// OperationNone is the zero value and names no operation.
	OperationNone Operation = iota
	// OperationGetService is the GET of the declared Service.
	OperationGetService
	// OperationListPods is the server-filtered Pod enumeration.
	OperationListPods
	// OperationListEndpointSlices is the server-filtered EndpointSlice
	// enumeration.
	OperationListEndpointSlices
)

// operationNames is indexed by Operation. Keep it aligned with the const block
// above; TestOperationNamesCoverEveryValue fails if the two drift apart.
var operationNames = [...]string{
	OperationNone:               "NONE",
	OperationGetService:         "SERVICE_GET",
	OperationListPods:           "POD_LIST",
	OperationListEndpointSlices: "ENDPOINTSLICE_LIST",
}

// String returns the canonical name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (o Operation) String() string {
	if int(o) >= len(operationNames) {
		return "Operation(" + strconv.FormatUint(uint64(o), 10) + ")"
	}
	return operationNames[o]
}

// Failure is the closed vocabulary of acquisition failures.
//
// # Every member is derived from structured information only
//
// An HTTP status code, a metav1.StatusReason through apierrors, a typed
// context error, or a typed crypto/x509 verification error. **Status.Message,
// Status.details.causes[].message and every condition or status message are
// never read, never matched, never parsed and never interpolated** — which keeps
// hostile status strings, ANSI and CRLF out structurally rather than by escaping
// them (ADR 0094 section 2.8).
//
// It is svcdoctor's own vocabulary rather than a Kubernetes one, so a new API
// reason cannot silently create a new svcdoctor state: anything unrecognized
// becomes FailureAPIError, which claims nothing beyond "the API server answered
// with an error this run does not interpret".
type Failure uint8

const (
	// FailureNone is the zero value: the operation succeeded.
	FailureNone Failure = iota

	// FailureUnauthorized is HTTP 401. It is authentication, not authorization:
	// the API server did not accept this run's identity at all.
	FailureUnauthorized

	// FailureForbidden is HTTP 403. The identity was accepted and this specific
	// read was refused.
	//
	// **A denied read is never emptiness.** The set it would have produced is
	// unavailable, not empty, and every universal claim over it is withheld.
	FailureForbidden

	// FailureNotFound is HTTP 404 on the Service GET: the API server reported
	// that no Service of this name exists in this namespace, at the time of this
	// observation.
	FailureNotFound

	// FailureResourceExpired is HTTP 410 during pagination: the continue token
	// is no longer usable.
	//
	// The enumeration becomes incomplete and is **never silently restarted**,
	// because a restart samples a different moment and would present two
	// enumerations as one.
	FailureResourceExpired

	// FailureAPIError is any other API status — a 5xx, a 429, a 409, anything
	// this run does not interpret.
	//
	// There is no retry. A 429 or a 5xx ends the read and the set becomes
	// incomplete, because retrying turns one bounded diagnosis into a small
	// monitoring loop.
	FailureAPIError

	// FailureTransport means no HTTP response was obtained at all.
	FailureTransport

	// FailureTLSUnknownAuthority means the API server's certificate did not
	// verify against the configured trust material. It is the most common
	// consequence of a kubeconfig whose CA does not belong to the cluster it
	// names.
	FailureTLSUnknownAuthority

	// FailureTLSHostnameMismatch means the certificate carried no name matching
	// the API server this target selected.
	FailureTLSHostnameMismatch

	// FailureTLSCertificateExpired means the API server's certificate is outside
	// its validity window.
	FailureTLSCertificateExpired

	// FailureTimeout means svcdoctor's own budget expired. It is not evidence
	// that the API server failed.
	FailureTimeout

	// FailureCancelled means the run was cancelled before this operation
	// concluded.
	FailureCancelled
)

// failureNames is indexed by Failure. Keep it aligned with the const block
// above; TestFailureNamesCoverEveryValue fails if the two drift apart.
var failureNames = [...]string{
	FailureNone:                  "NONE",
	FailureUnauthorized:          "UNAUTHORIZED",
	FailureForbidden:             "FORBIDDEN",
	FailureNotFound:              "NOT_FOUND",
	FailureResourceExpired:       "RESOURCE_EXPIRED",
	FailureAPIError:              "API_ERROR",
	FailureTransport:             "TRANSPORT",
	FailureTLSUnknownAuthority:   "TLS_UNKNOWN_AUTHORITY",
	FailureTLSHostnameMismatch:   "TLS_HOSTNAME_MISMATCH",
	FailureTLSCertificateExpired: "TLS_CERTIFICATE_EXPIRED",
	FailureTimeout:               "TIMEOUT",
	FailureCancelled:             "CANCELLED",
}

// String returns the canonical name. It never fails.
func (f Failure) String() string {
	if int(f) >= len(failureNames) {
		return "Failure(" + strconv.FormatUint(uint64(f), 10) + ")"
	}
	return failureNames[f]
}

// StopReason is the closed vocabulary for why an enumeration stopped.
//
// **Only StopComplete admits a universal claim.** Every other member means the
// set is incomplete, and an incomplete set supports no "zero", "all", "none" or
// "only" statement of any kind. That is Kafka Phase 10.2's rule, unchanged, in a
// third domain (ADR 0094 section 2.5).
type StopReason uint8

const (
	// StopComplete means every page was followed, no continue token remained,
	// and no budget was reached.
	StopComplete StopReason = iota
	// StopPageLimit means the per-list page ceiling was reached with a continue
	// token still outstanding.
	StopPageLimit
	// StopObjectLimit means the object budget was reached.
	StopObjectLimit
	// StopEndpointLimit means the aggregate endpoint budget was reached while a
	// returned page was being normalized.
	StopEndpointLimit
	// StopResourceExpired means a 410 ended the enumeration.
	StopResourceExpired
	// StopCancelled means the run's context ended mid-enumeration.
	StopCancelled
	// StopRequestFailed means a request failed for any other reason.
	StopRequestFailed
)

// stopReasonNames is indexed by StopReason. Keep it aligned with the const block
// above; TestStopReasonNamesCoverEveryValue fails if the two drift apart.
var stopReasonNames = [...]string{
	StopComplete:        "COMPLETE",
	StopPageLimit:       "INCOMPLETE_PAGE_LIMIT",
	StopObjectLimit:     "INCOMPLETE_OBJECT_LIMIT",
	StopEndpointLimit:   "INCOMPLETE_ENDPOINT_LIMIT",
	StopResourceExpired: "INCOMPLETE_RESOURCE_EXPIRED",
	StopCancelled:       "INCOMPLETE_CANCELLED",
	StopRequestFailed:   "INCOMPLETE_REQUEST_FAILED",
}

// String returns the canonical name. It never fails.
func (s StopReason) String() string {
	if int(s) >= len(stopReasonNames) {
		return "StopReason(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return stopReasonNames[s]
}

// SkipReason is the closed vocabulary for why a stage did not run at all.
//
// A skipped stage is not a failed one and is never an empty one. It records that
// svcdoctor deliberately did not measure something, and what stopped it.
type SkipReason uint8

const (
	// SkipNone is the zero value: the stage was attempted.
	SkipNone SkipReason = iota
	// SkipAPIAccessFailed means the API server did not accept this run's
	// identity, so nothing below it was read.
	SkipAPIAccessFailed
	// SkipServiceUnavailable means the Service GET did not produce a Service —
	// it was not found, was denied, or failed.
	SkipServiceUnavailable
	// SkipSelectorLess means the Service selects no Pods by label, so there is no
	// Pod list to issue.
	//
	// **An empty selector map is selector-less, not match-all.** Listing all Pods
	// in the namespace and calling them this Service's backends is the single
	// mistake that would turn a correctly configured selector-less Service into a
	// claim that its backends vanished.
	SkipSelectorLess
	// SkipUnsupportedServiceType means the Service's type has no backend
	// publication to measure — ExternalName, or a type this build does not
	// recognize.
	SkipUnsupportedServiceType
	// SkipCancelled means the run's budget ended before the stage was reached.
	SkipCancelled
)

// skipReasonNames is indexed by SkipReason. Keep it aligned with the const block
// above; TestSkipReasonNamesCoverEveryValue fails if the two drift apart.
var skipReasonNames = [...]string{
	SkipNone:                   "NONE",
	SkipAPIAccessFailed:        "API_ACCESS_FAILED",
	SkipServiceUnavailable:     "SERVICE_UNAVAILABLE",
	SkipSelectorLess:           "SELECTOR_LESS",
	SkipUnsupportedServiceType: "UNSUPPORTED_SERVICE_TYPE",
	SkipCancelled:              "CANCELLED",
}

// String returns the canonical name. It never fails.
func (s SkipReason) String() string {
	if int(s) >= len(skipReasonNames) {
		return "SkipReason(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return skipReasonNames[s]
}

// Stage is what happened to one acquisition step that is not an enumeration.
//
// The zero Stage is a stage that was never reached, which is what a caller sees
// for everything below a failure.
type Stage struct {
	// Attempted reports whether a request was issued for this stage.
	Attempted bool

	// Skip says why the stage did not run. Meaningful only when Attempted is
	// false, and always set in that case.
	Skip SkipReason

	// Failure classifies a non-success. FailureNone with Attempted true is a
	// success.
	Failure Failure

	// StartedAt and Elapsed are the measurement window. Elapsed is zero for a
	// stage that was never attempted, and the caller records that as unmeasured
	// rather than as an instantaneous step.
	StartedAt time.Time
	Elapsed   time.Duration
}

// OK reports that the stage ran and succeeded.
func (s Stage) OK() bool { return s.Attempted && s.Failure == FailureNone }

// Enumeration is what happened to one bounded, paginated list.
//
// # A count is authoritative only when Complete is true
//
// Observed is *observed so far* for every other stop reason, and no consumer may
// turn it into a universal claim. That distinction is the whole reason this is a
// struct rather than an integer: reaching a budget produces a number **and** the
// fact that the number is not a total, and the two must travel together or the
// second gets lost.
type Enumeration struct {
	// Op names which list this was.
	Op Operation

	// Attempted reports whether any request was issued.
	Attempted bool

	// Skip says why the enumeration did not run. Meaningful only when Attempted
	// is false, and always set in that case.
	Skip SkipReason

	// Stop says why it stopped. Meaningful only when Attempted is true.
	Stop StopReason

	// Failure classifies a request-level failure, if there was one.
	Failure Failure

	// Pages is how many responses were consumed.
	Pages int

	// Observed is how many objects were seen. A total only when Complete.
	Observed int

	StartedAt time.Time
	Elapsed   time.Duration
}

// Complete reports that the enumeration was exhaustive.
//
// **This is the only predicate that admits a universal claim over the set**, and
// it is deliberately conjunctive: the list must have been attempted *and* have
// stopped because there was nothing left. An enumeration that was skipped is not
// complete — nothing was enumerated — and neither is one that stopped at a
// ceiling.
func (e Enumeration) Complete() bool { return e.Attempted && e.Stop == StopComplete }

// ServiceFacts is everything svcdoctor retains about the Service object.
//
// Four fields, and every one of them is consumed by the frozen contract. **No
// label, no annotation, no cluster IP, no port list, no resourceVersion and no
// UID.** The UID is used inside this package to guard the delete-and-recreate
// race and never leaves it; only the count of what it excluded does.
type ServiceFacts struct {
	// Type is one of servicekubernetes.ServiceType*. An unrecognized value
	// becomes ServiceTypeUnknown, so a hostile or future spec.type cannot reach
	// a report and cannot unlock behaviour.
	Type string

	// Headless reports `clusterIP: None`. It is never a fault.
	Headless bool

	// SelectorPresent reports that the Service selects Pods by label. **An empty
	// map is selector-less**, identically to an absent one.
	SelectorPresent bool

	// SelectorKeyCount is how many keys the selector holds. The count, never the
	// keys and never the values.
	SelectorKeyCount int
}

// PublicationFacts is everything svcdoctor retains about published endpoints.
//
// Counts and one boolean. **No address, no hostname, no zone, no node name, no
// targetRef name and no slice name.** The deduplication key is computed and
// discarded inside this package.
type PublicationFacts struct {
	// Slices is how many associated EndpointSlices were admitted.
	Slices int

	// Endpoints is how many distinct endpoints they published, deduplicated.
	Endpoints int

	// ReadyEndpoints is how many are effective-ready, by `conditions.ready`
	// alone with nil read as true.
	ReadyEndpoints int

	// TerminatingEndpoints is how many report `terminating: true`. Disclosure,
	// never health: such an endpoint is not dead, and proxies may still route to
	// it when every available endpoint is terminating.
	TerminatingEndpoints int

	// ExcludedByOwnerUID is how many labelled slices named a different Service
	// generation and were excluded.
	ExcludedByOwnerUID int

	// ExternallyManaged reports that at least one admitted slice is managed by
	// something other than the built-in controller. It does not gate admission.
	ExternallyManaged bool
}

// Result is everything one Kubernetes acquisition produced.
//
// It is svcdoctor's own type throughout. **No Kubernetes API struct is reachable
// from it**, by construction rather than by convention: every field is a scalar,
// a closed enum or a struct of those, so there is no path by which a decoded
// corev1.Service, corev1.Pod or discoveryv1.EndpointSlice could travel past this
// package. Each decoded object is read for the fields below and discarded
// immediately.
//
// It is descriptive and never interpretive. "The Service GET returned 403" is a
// fact; "access is denied so the deployment is broken" is a finding, and no
// finding is produced here (ADR 0094 section 2.12).
type Result struct {
	// Target restates what was asked for, so a consumer needs no second source.
	Target Target

	// Authority is the validated API authority. It holds no secret.
	Authority Authority

	// APIAccess records whether the API server accepted this run's identity.
	//
	// It PASSes as soon as any HTTP status other than 401 comes back, because
	// every other status is an answer from a server that authenticated the
	// request. It fails on a 401 and on a transport or TLS failure, and in both
	// cases nothing below it runs.
	APIAccess Stage

	// Service records the GET.
	Service Stage

	// ServiceFacts is meaningful only when Service.OK() is true.
	ServiceFacts ServiceFacts

	// Pods records the server-filtered Pod enumeration.
	Pods Enumeration

	// Publication records the server-filtered EndpointSlice enumeration.
	Publication Enumeration

	// PublicationFacts is meaningful only when Publication was attempted, and its
	// counts are totals only when Publication.Complete() is true.
	PublicationFacts PublicationFacts

	// Requests is how many API round trips the acquisition made.
	//
	// It exists so the frozen ceiling of 17 is a measured property rather than an
	// arithmetic claim, and so a test can assert that client construction issues
	// no discovery request of its own.
	Requests int
}

// Incomplete reports that svcdoctor did not finish measuring what it set out to.
//
// It is deliberately **not** derived from whether anything failed. A denied read
// is a completed measurement of a refusal; an enumeration that hit a page
// ceiling is an unfinished measurement of a set. The first is a fact about the
// target and the second is a fact about the run, and only the second belongs
// here — because only the second is what exit code 4 means (ADR 0074).
//
// An enumeration that was deliberately skipped — a selector-less Service, an
// ExternalName Service — does not make a run incomplete. Nothing was left
// unmeasured: there was nothing there to measure.
func (r Result) Incomplete() bool {
	switch {
	case r.APIAccess.Attempted && r.APIAccess.unfinished():
		return true
	case r.Service.Attempted && r.Service.unfinished():
		return true
	case r.Pods.Attempted && !r.Pods.Complete():
		return true
	case r.Publication.Attempted && !r.Publication.Complete():
		return true
	case !r.APIAccess.Attempted && r.APIAccess.Skip == SkipCancelled:
		return true
	}
	return false
}

// unfinished reports that a stage was attempted and produced no answer either
// way — as opposed to producing the answer "denied" or "not found", which are
// answers.
func (s Stage) unfinished() bool {
	switch s.Failure {
	case FailureTimeout, FailureCancelled, FailureAPIError, FailureResourceExpired:
		return true
	}
	return false
}
