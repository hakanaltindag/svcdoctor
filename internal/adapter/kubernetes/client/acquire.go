package client

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// Params describes one Kubernetes acquisition.
type Params struct {
	// Target is the declared namespace and Service, and the API authority.
	Target Target

	// Credential is the bearer token the target's own credential reference
	// named, already bound to the API server's endpoint. It may be zero, in
	// which case the kubeconfig or the projected ServiceAccount supplies the
	// credential instead.
	Credential security.Credential

	// Budgets bound the acquisition. The zero value means the frozen defaults.
	Budgets Budgets
}

// Acquire performs the three bounded reads and returns normalized facts.
//
// # Exactly three operations, in one order, issued sequentially
//
//	GET  Service
//	LIST Pods            ?labelSelector=<the Service's own selector>&limit=500
//	LIST EndpointSlices  ?labelSelector=kubernetes.io/service-name=<name>&limit=500
//
// The GET must complete first because it yields the selector the Pod list needs
// and the UID the slice list validates against. The two lists are issued
// **sequentially rather than concurrently**: two goroutines would make the
// interleaving of two non-atomic reads non-deterministic for no measurable gain
// on three requests, and determinism is worth more here than a few milliseconds.
//
// # Server-side filtering is mandatory
//
// The API server evaluates both label selectors. svcdoctor does **not** list
// every Pod and match locally: server-side selection is exact Kubernetes
// semantics rather than a reimplementation of them, it bounds cardinality at the
// source, and it is what lets Phase 12.1C's selector finding mean *"a complete
// server-filtered list was empty"*. It narrows the request and it does **not**
// narrow the RBAC grant, which stays `pods:list` and `endpointslices:list` for
// the whole namespace.
//
// # An error means the run could not be performed
//
// A refused target, an unreadable kubeconfig, a credential bound elsewhere. Every
// *diagnostic* outcome is a Result: a Service that does not exist, a read that
// was denied, an enumeration that hit a ceiling and a cancelled run all return a
// Result describing exactly that, and produce no error at all.
func Acquire(ctx context.Context, params Params) (Result, error) {
	budgets := params.Budgets.orDefault()
	if err := budgets.validate(); err != nil {
		return Result{}, err
	}

	connection, err := Connect(params.Target, params.Credential)
	if err != nil {
		return Result{}, err
	}
	return acquireWith(ctx, connection, params.Target, budgets)
}

// acquireWith is Acquire over an already-built connection.
//
// Separate so that a hermetic test can drive acquisition against a connection it
// constructed, and so that the request counter starts at zero after client
// construction — which is what makes "client construction issues no request of
// its own" an assertion rather than an assumption.
func acquireWith(
	ctx context.Context, connection *Connection, target Target, budgets Budgets,
) (Result, error) {
	result := Result{Target: target, Authority: connection.authority}

	service, ok := readService(ctx, connection, target, &result)
	if !ok {
		return result, nil
	}
	result.ServiceFacts = normalizeService(service)

	pods, slices := plannedReads(result.ServiceFacts)
	if pods {
		result.Pods = listPods(
			ctx, connection, target, service.Spec.Selector, budgets, &result.Requests)
	} else {
		result.Pods = skippedEnumeration(OperationListPods, skipReasonFor(result.ServiceFacts))
	}

	// **The two branches are independent.** A denied or failed Pod list does not
	// stop the EndpointSlice read: the two sets answer different questions, they
	// are siblings under the Service node rather than a chain, and erasing one
	// because the other failed would discard evidence svcdoctor already holds
	// (ADR 0094 section 10.8).
	switch {
	case !slices:
		result.Publication = skippedEnumeration(
			OperationListEndpointSlices, skipReasonFor(result.ServiceFacts))
	case ctx.Err() != nil:
		result.Publication = skippedEnumeration(OperationListEndpointSlices, SkipCancelled)
	default:
		result.Publication, result.PublicationFacts = listEndpointSlices(
			ctx, connection, target, string(service.UID), budgets, &result.Requests)
	}
	return result, nil
}

// readService performs the GET and decides whether anything below it may run.
//
// It also decides the api_access node, and the rule is exact: **a 401 is the only
// status that means the API server did not accept this run's identity.** Every
// other status — 403, 404, 409, 429, 500 — is an answer from a server that
// authenticated the request, so api_access passes and the refusal belongs to the
// operation that received it. A transport or TLS failure means no answer arrived
// at all, so api_access fails and nothing below it is attempted.
func readService(
	ctx context.Context, connection *Connection, target Target, result *Result,
) (*corev1.Service, bool) {
	started := time.Now()
	result.APIAccess = Stage{Attempted: true, StartedAt: started}
	result.Service = Stage{Attempted: true, StartedAt: started}

	if err := ctx.Err(); err != nil {
		failure := classify(ctx, err)
		result.APIAccess = Stage{Attempted: false, Skip: SkipCancelled, Failure: failure}
		result.Service = skippedStage(SkipCancelled)
		result.Pods = skippedEnumeration(OperationListPods, SkipCancelled)
		result.Publication = skippedEnumeration(OperationListEndpointSlices, SkipCancelled)
		return nil, false
	}

	service, err := connection.core.Services(target.Namespace).
		Get(ctx, target.ServiceName, metav1.GetOptions{})
	result.Requests++
	elapsed := time.Since(started)
	result.APIAccess.Elapsed = elapsed
	result.Service.Elapsed = elapsed

	failure := classify(ctx, err)
	switch failure {
	case FailureNone:
		return service, true

	case FailureUnauthorized, FailureTransport, FailureTLSUnknownAuthority,
		FailureTLSHostnameMismatch, FailureTLSCertificateExpired,
		FailureTimeout, FailureCancelled:
		// No answer, or an answer that refused the identity itself. The API
		// access node carries it and everything below is blocked, because
		// nothing below was measured.
		result.APIAccess.Failure = failure
		result.Service = skippedStage(SkipAPIAccessFailed)
		result.Pods = skippedEnumeration(OperationListPods, SkipAPIAccessFailed)
		result.Publication = skippedEnumeration(
			OperationListEndpointSlices, SkipAPIAccessFailed)
		return nil, false

	default:
		// 403, 404 and every other API status: the server authenticated the
		// request and answered. The Service read carries the outcome; the two
		// reads below it do not run, because both need the Service.
		result.Service.Failure = failure
		result.Pods = skippedEnumeration(OperationListPods, SkipServiceUnavailable)
		result.Publication = skippedEnumeration(
			OperationListEndpointSlices, SkipServiceUnavailable)
		return nil, false
	}
}

func skippedStage(reason SkipReason) Stage {
	return Stage{Attempted: false, Skip: reason}
}

// plannedReads decides which of the two lists this Service admits.
//
// Frozen by ADR 0094 sections 2.4 and 10.8, and the two refusals are different
// facts:
//
//   - **ExternalName and any unrecognized type** publish no backend at all.
//     Absent slices there are correct rather than a fault, and neither list is
//     issued.
//   - **A selector-less Service** — including one whose selector is an empty map
//     — has endpoints managed by something svcdoctor did not observe. Neither
//     list is issued, because a Pod list would need a selector that does not
//     exist and a slice count would invite a conclusion about a publication
//     svcdoctor cannot attribute.
//
// **An empty selector map is never match-all.** That single reading is the one
// mistake that would turn a correctly configured selector-less Service into a
// claim that its backends vanished, which is why it is decided once, here.
func plannedReads(facts ServiceFacts) (pods, slices bool) {
	switch facts.Type {
	case servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer:
	default:
		return false, false
	}
	if !facts.SelectorPresent {
		return false, false
	}
	return true, true
}

func skipReasonFor(facts ServiceFacts) SkipReason {
	switch facts.Type {
	case servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer:
		return SkipSelectorLess
	default:
		return SkipUnsupportedServiceType
	}
}

// normalizeService retains four facts and discards the object.
//
// **No label, no annotation, no cluster IP, no port, no resourceVersion and no
// UID leaves this function.** The UID is read by the caller for the
// owner-reference guard and never enters a Result.
func normalizeService(service *corev1.Service) ServiceFacts {
	return ServiceFacts{
		Type: normalizeServiceType(service.Spec.Type),
		// `clusterIP: None` is the whole definition of headless, and it is never
		// a fault. The value itself is not retained: an address belongs to the
		// cluster's own topology, and no admitted finding reads one.
		Headless: service.Spec.ClusterIP == corev1.ClusterIPNone,
		// An empty map and an absent one are the same fact, which is exactly what
		// len expresses and what a nil check would not.
		SelectorPresent:  len(service.Spec.Selector) > 0,
		SelectorKeyCount: len(service.Spec.Selector),
	}
}

// normalizeServiceType maps the peer's value onto svcdoctor's closed set.
//
// A value this build does not recognize becomes ServiceTypeUnknown, which
// plannedReads treats as unsupported. **An unrecognized value never unlocks
// behaviour**: a future or hostile `spec.type` produces fewer reads and fewer
// claims, never more.
//
// The empty string is ClusterIP because that is the API's own declared default
// for `spec.type`, applied server-side on every Service that omits it.
func normalizeServiceType(t corev1.ServiceType) string {
	switch t {
	case corev1.ServiceTypeClusterIP, "":
		return servicekubernetes.ServiceTypeClusterIP
	case corev1.ServiceTypeNodePort:
		return servicekubernetes.ServiceTypeNodePort
	case corev1.ServiceTypeLoadBalancer:
		return servicekubernetes.ServiceTypeLoadBalancer
	case corev1.ServiceTypeExternalName:
		return servicekubernetes.ServiceTypeExternalName
	default:
		return servicekubernetes.ServiceTypeUnknown
	}
}

// listPods enumerates the Pods the Service's own selector matches.
//
// # Nothing about a Pod is retained
//
// Not a name, a UID, a label, a phase, a readiness condition, a container
// status, a restart count, an image, a node name or an IP. The whole of what
// this produces is *how many* and *was the enumeration exhaustive*, because no
// admitted finding consumes a single Pod field and retaining identity for a
// rendering nobody's diagnosis depends on is the debt ADR 0090 section 7
// refuses. Each decoded page is counted and dropped.
//
// The selector is serialized by k8s.io/apimachinery/pkg/labels, which is exact
// Kubernetes semantics. Nothing here builds a selector string by hand, escapes
// anything, or matches a label locally.
func listPods(
	ctx context.Context, connection *Connection, target Target,
	selector map[string]string, budgets Budgets, requests *int,
) Enumeration {
	return paginate(
		ctx, OperationListPods, budgets, labels.Set(selector).String(), budgets.MaxPods,
		func(ctx context.Context, options metav1.ListOptions) (page[corev1.Pod], error) {
			list, err := connection.core.Pods(target.Namespace).List(ctx, options)
			if err != nil {
				return page[corev1.Pod]{}, err
			}
			return page[corev1.Pod]{items: list.Items, next: list.Continue}, nil
		},
		func(items []corev1.Pod) (int, StopReason) { return len(items), StopComplete },
		requests,
	)
}

// listEndpointSlices enumerates the slices Kubernetes associates with the
// Service, and normalizes what they publish.
//
// The association is the `kubernetes.io/service-name` label applied
// **server-side**, plus the owner-reference UID guard. There is no name prefix
// match, no name similarity, no IP matching, no fuzzy label search and no
// heuristic of any kind.
func listEndpointSlices(
	ctx context.Context, connection *Connection, target Target,
	serviceUID string, budgets Budgets, requests *int,
) (Enumeration, PublicationFacts) {
	accumulator := &publicationAccumulator{
		serviceUID:   serviceUID,
		maxEndpoints: budgets.MaxEndpoints,
		seen:         make(map[string]struct{}),
	}
	selector := labels.Set{discoveryv1.LabelServiceName: target.ServiceName}.String()

	enumeration := paginate(
		ctx, OperationListEndpointSlices, budgets, selector, budgets.MaxSlices,
		func(ctx context.Context, options metav1.ListOptions) (page[discoveryv1.EndpointSlice], error) {
			list, err := connection.discovery.EndpointSlices(target.Namespace).List(ctx, options)
			if err != nil {
				return page[discoveryv1.EndpointSlice]{}, err
			}
			return page[discoveryv1.EndpointSlice]{items: list.Items, next: list.Continue}, nil
		},
		accumulator.consume,
		requests,
	)
	return enumeration, accumulator.facts
}

// publicationAccumulator normalizes EndpointSlices across pages.
//
// It carries state across pages for one reason only: deduplication. An endpoint
// may legitimately appear in more than one slice, and dual-stack guarantees
// separate slices per family, so a count that did not deduplicate would
// double-count a backend and produce a number nobody could reconcile with
// `kubectl`.
type publicationAccumulator struct {
	// serviceUID is the Service generation this run read. It is a plain string
	// rather than the API's own UID type, which is what keeps the client-go
	// import allowlist at exactly the ten paths ADR 0094 §2.1 enumerated.
	serviceUID   string
	maxEndpoints int

	// seen holds deduplication keys. They are built from targetRef or from the
	// address tuple, are compared, and are **discarded with this value** — no key
	// reaches a Result, evidence or a report.
	seen map[string]struct{}

	facts PublicationFacts
}

// builtInSliceManagers are the controllers Kubernetes itself ships.
//
// A slice managed by anything else is recorded as externally managed, and is
// **still admitted**: a third-party-managed slice carrying the authoritative
// Service association is a published backend, and excluding it would make
// svcdoctor's answer disagree with kube-proxy's. `managed-by` is a disclosure,
// never an admission gate.
var builtInSliceManagers = []string{
	"endpointslice-controller.k8s.io",
	"endpointslicemirroring-controller.k8s.io",
}

func (a *publicationAccumulator) consume(items []discoveryv1.EndpointSlice) (int, StopReason) {
	// **Sorted before anything is counted.** The API's list order must not reach
	// a normalized value, and it can: where the endpoint ceiling truncates an
	// enumeration, which endpoints were counted depends entirely on the order
	// they arrived in. Sorting makes a permuted page produce identical counts.
	ordered := slices.Clone(items)
	slices.SortStableFunc(ordered, func(x, y discoveryv1.EndpointSlice) int {
		if c := strings.Compare(x.Namespace, y.Namespace); c != 0 {
			return c
		}
		return strings.Compare(x.Name, y.Name)
	})

	for i := range ordered {
		slice := &ordered[i]
		if !a.associated(slice) {
			a.facts.ExcludedByOwnerUID++
			continue
		}
		a.facts.Slices++
		if externallyManaged(slice) {
			a.facts.ExternallyManaged = true
		}
		if stop := a.consumeEndpoints(slice); stop != StopComplete {
			return len(items), stop
		}
	}
	return len(items), StopComplete
}

// associated applies the frozen Service identity guard.
//
// A Service may be deleted and recreated between the GET and this LIST, and
// association by the `kubernetes.io/service-name` label is **name**-based, so it
// would silently cross generations. Each slice carries an owner reference to its
// Service, and an owner reference carries the UID:
//
//   - an owner reference to a Service whose UID differs is **excluded and
//     counted**;
//   - a slice with **no** Service owner reference is **included** by label
//     association, because a Service may legitimately publish slices it does not
//     own and refusing them would make svcdoctor disagree with kube-proxy.
//
// No fourth API call is added. The owner reference gives the same guarantee for
// free, and a re-GET would only move the race.
//
// The comparison is on UID and on nothing else. A matching owner *name* with a
// different UID is exactly the case this exists to catch, so the name is never
// consulted.
func (a *publicationAccumulator) associated(slice *discoveryv1.EndpointSlice) bool {
	for _, owner := range slice.OwnerReferences {
		if owner.Kind != "Service" || owner.APIVersion != "v1" {
			continue
		}
		return string(owner.UID) == a.serviceUID
	}
	return true
}

func externallyManaged(slice *discoveryv1.EndpointSlice) bool {
	manager, ok := slice.Labels[discoveryv1.LabelManagedBy]
	if !ok || manager == "" {
		return false
	}
	return !slices.Contains(builtInSliceManagers, manager)
}

// consumeEndpoints counts one slice's endpoints under the aggregate ceiling.
//
// The ceiling is checked **before** an endpoint is counted, so reaching it
// produces an incomplete enumeration rather than a partially consumed page
// presented as a total.
func (a *publicationAccumulator) consumeEndpoints(slice *discoveryv1.EndpointSlice) StopReason {
	portKey := portsKey(slice.Ports)

	ordered := slices.Clone(slice.Endpoints)
	slices.SortStableFunc(ordered, func(x, y discoveryv1.Endpoint) int {
		return strings.Compare(endpointOrderKey(x), endpointOrderKey(y))
	})

	for i := range ordered {
		endpoint := &ordered[i]
		key := deduplicationKey(slice, endpoint, portKey)
		if _, duplicate := a.seen[key]; duplicate {
			continue
		}
		if a.facts.Endpoints >= a.maxEndpoints {
			return StopEndpointLimit
		}
		a.seen[key] = struct{}{}
		a.facts.Endpoints++

		if EffectiveReady(endpoint.Conditions.Ready) {
			a.facts.ReadyEndpoints++
		}
		if EffectiveTerminating(endpoint.Conditions.Terminating) {
			a.facts.TerminatingEndpoints++
		}
	}
	return StopComplete
}

// deduplicationKey identifies one published endpoint.
//
// targetRef when present — namespace, name and UID, which is what makes two
// slices publishing one Pod one backend — and the address tuple otherwise,
// because a Service may legitimately publish endpoints no Pod backs and those
// still have to be told apart.
//
// The key is compared and discarded. **No part of it reaches a Result**, which
// is what keeps addresses, hostnames and targetRef names out of the report while
// still producing a count a reader can reconcile.
func deduplicationKey(
	slice *discoveryv1.EndpointSlice, endpoint *discoveryv1.Endpoint, portKey string,
) string {
	if ref := endpoint.TargetRef; ref != nil {
		return "ref\x00" + ref.Namespace + "\x00" + ref.Name + "\x00" + string(ref.UID)
	}
	return "addr\x00" + string(slice.AddressType) + "\x00" +
		strings.Join(sortedCopy(endpoint.Addresses), ",") + "\x00" + portKey
}

// endpointOrderKey orders endpoints within a slice deterministically.
func endpointOrderKey(endpoint discoveryv1.Endpoint) string {
	key := strings.Join(sortedCopy(endpoint.Addresses), ",")
	if ref := endpoint.TargetRef; ref != nil {
		key += "\x00" + ref.Namespace + "\x00" + ref.Name + "\x00" + string(ref.UID)
	}
	return key
}

func portsKey(ports []discoveryv1.EndpointPort) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		part := ""
		if port.Port != nil {
			part = strconv.Itoa(int(*port.Port))
		}
		parts = append(parts, part)
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// EffectiveReady applies the frozen nil semantics for `conditions.ready`.
//
//	ready == nil  =>  true
//
// **`ready` alone decides ready.** It consults no `serving`, no `terminating`,
// no targetRef, no address, no port, no address type and no Pod, because `ready`
// already *is* Kubernetes' shortcut for "serving and not terminating". Adding a
// second condition would re-derive a value Kubernetes publishes, and would
// silently change meaning for a Service with `publishNotReadyAddresses: true`
// (ADR 0094 section 2.6).
//
// It is exported so that the semantics can be asserted directly rather than only
// through a count.
func EffectiveReady(ready *bool) bool { return ready == nil || *ready }

// EffectiveServing applies the frozen nil semantics for `conditions.serving`.
//
//	serving == nil  =>  true
//
// It is normalized because the contract froze all three, and it is deliberately
// **not** consulted by any count: a `serving=true, ready=false,
// terminating=true` endpoint is not ready and is also not dead, and substituting
// serving for ready would silently change what "published as ready" means.
func EffectiveServing(serving *bool) bool { return serving == nil || *serving }

// EffectiveTerminating applies the frozen nil semantics for
// `conditions.terminating`.
//
//	terminating == nil  =>  false
//
// The asymmetry with the other two is Kubernetes' own: an endpoint that says
// nothing about termination is not terminating. `terminating` is stable only
// from Kubernetes v1.26 while the supported floor is v1.21, so on an older
// server the field is simply absent and this reads false — which is the same
// answer a v1.26 server gives for an endpoint that is not terminating.
func EffectiveTerminating(terminating *bool) bool {
	return terminating != nil && *terminating
}
