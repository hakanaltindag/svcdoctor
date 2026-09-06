package kubernetes

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// The steps one Kubernetes Service diagnosis records.
//
// Five, because five things are separately true, and ADR 0094 section 2.9 froze
// exactly this shape:
//
//	k8s.target  L0  ->  k8s.api_access  L5
//	                        ->  k8s.service  L6
//	                                ->  k8s.pod_set              L6
//	                                ->  k8s.endpoint_publication L6
//
// L1 through L3 are unused because transport belongs to the client library, and
// L4 is unused because the Kubernetes API has no separate capability-discovery
// step. Both absences are deliberate; the failure boundary needs only *a* PASS
// at a strictly lower layer, and L0 provides one.
//
// **The Pod set and the endpoint publication are siblings under the Service
// node, not a chain.** That is what makes the graph a DAG rather than a list,
// and it is what lets a denied Pod list leave the EndpointSlice evidence intact
// (ADR 0094 section 10.8).
//
// The string values are part of the report contract and are matched by
// automation; see docs/FINDINGS.md section 2 on why a step name is not renamed
// casually.
const (
	// StepTarget names the L0 fact that a run accepted a namespace and a Service
	// name as its input.
	//
	// It is the Kubernetes counterpart of vocabulary.StepTargetRequested and
	// exists for the same reason that step is separate: the requested target is
	// an input fact, not a measurement. It is separate rather than shared
	// because its subject is a Kubernetes object reference rather than a
	// host:port, and reusing the transport anchor would publish the API server's
	// address as the run's target — which ADR 0094 section 2.4 forbids.
	StepTarget domain.Step = "k8s.target"

	// StepAPIAccess names the fact that the Kubernetes API server accepted this
	// run's identity, or did not.
	//
	// It is L5 because it is authentication: everything below it is a read the
	// API server authorized. A 401 fails this node; a 403 does not, because a
	// 403 means the identity was accepted and one specific read was refused.
	StepAPIAccess domain.Step = "k8s.api_access"

	// StepService names the GET of the declared Service.
	StepService domain.Step = "k8s.service"

	// StepPodSet names the server-filtered Pod enumeration.
	//
	// **The node is the set, never a Pod.** No per-Pod evidence node exists and
	// none may be added: no admitted finding consumes a single Pod field, and
	// retaining identity for a rendering nobody's diagnosis depends on is the
	// debt ADR 0090 section 7 refuses (ADR 0094 section 11.2).
	StepPodSet domain.Step = "k8s.pod_set"

	// StepEndpointPublication names the EndpointSlice enumeration.
	//
	// It is named after what it measures rather than after the API object: the
	// question is what Kubernetes *publishes* for this Service, and "publishes"
	// is the wording the whole contract uses in place of "reachable"
	// (ADR 0093 section 2.5). svcdoctor never connects to an endpoint here.
	StepEndpointPublication domain.Step = "k8s.endpoint_publication"
)

// AttrAuthMode is the category of credential this run presented to the API
// server.
//
// **It is a category, never material.** One of four svcdoctor-declared values,
// recorded so that the authority a report was produced under can be
// reconstructed by a reader who was not there. A token, a private key, a
// certificate, a credential path and a kubeconfig path all stay out of evidence
// entirely (ADR 0094 section 11.3).
const AttrAuthMode domain.AttributeKey = "k8s.auth_mode"

// AttrContext is the kubeconfig context this run selected.
//
// Identity-kinded, so structural redaction pseudonymizes it in a shareable
// report. It is recorded because it is the operator-local input choice that
// decides which cluster was read, and a report whose reader cannot tell which
// context produced it is one nobody can reconcile with `kubectl`.
//
// Absent in in-cluster mode, where there is no context and naming one would be
// an invention.
const AttrContext domain.AttributeKey = "k8s.context"

// AttrNamespace is the namespace the target declared.
//
// Identity-kinded. AttrKindIdentity's definition already covers *"a named
// resource"*, so redaction transforms it by dispatching on the kind and needs no
// Kubernetes-specific mechanism.
const AttrNamespace domain.AttributeKey = "k8s.namespace"

// AttrServiceName is the Service the target declared.
//
// Identity-kinded, for the reason AttrNamespace is.
const AttrServiceName domain.AttributeKey = "k8s.service_name"

// AttrServiceType is the Service's type, from a closed set.
//
// One of ServiceTypeClusterIP, ServiceTypeNodePort, ServiceTypeLoadBalancer,
// ServiceTypeExternalName or ServiceTypeUnknown. A value the API server reports
// that svcdoctor does not recognize becomes ServiceTypeUnknown rather than
// reaching a report, and an unknown type is treated as unsupported for backend
// publication — an unrecognized value never produces stronger behaviour.
//
// **Service type is never equated with external reachability.** A LoadBalancer
// with ready endpoints may be externally unreachable, and a ClusterIP with none
// may be exactly what was intended.
const AttrServiceType domain.AttributeKey = "k8s.service_type"

// AttrServiceHeadless reports that the Service has no cluster IP.
//
// Rendering only, permanently. `clusterIP: None` is a deliberate configuration
// and never a fault, and no admitted finding reads this key.
const AttrServiceHeadless domain.AttributeKey = "k8s.service_headless"

// AttrSelectorPresent reports that the Service selects Pods by label.
//
// **An empty selector map is selector-less, not match-all.** That is the whole
// reason this is a boolean the adapter computes rather than something a rule
// derives from a count: reading an absent selector as "matches everything" is
// the single mistake that would turn a correctly configured selector-less
// Service into a claim that its backends vanished (ADR 0094 section 7.4).
const AttrSelectorPresent domain.AttributeKey = "k8s.selector_present"

// AttrSelectorKeyCount is how many label keys the selector holds.
//
// The count and never the keys, and never the values. A label key or value is
// operator-chosen text from a cluster's own configuration, and ADR 0094
// section 11.2 keeps every one of them out of evidence. The count is what makes
// "the selector was non-trivial" auditable without publishing what it selected
// on.
const AttrSelectorKeyCount domain.AttributeKey = "k8s.selector_key_count"

// AttrPodSetComplete reports that the Pod enumeration was exhaustive.
//
// **A count is authoritative only when this is true.** An incomplete
// enumeration supports no universal claim at all: not "zero", not "all", not
// "none", not "only". Reaching a page ceiling or an object budget produces an
// incomplete set, never an empty one, and an empty *complete* set is a different
// fact from an unavailable one (ADR 0094 section 2.5).
const AttrPodSetComplete domain.AttributeKey = "k8s.pod_set_complete"

// AttrPodObservedCount is how many Pods the server-filtered enumeration
// returned.
//
// It is *observed so far* whenever AttrPodSetComplete is false, and a consumer
// that reads one without the other is reading a number that may not be a total.
const AttrPodObservedCount domain.AttributeKey = "k8s.pod_observed_count"

// AttrSliceSetComplete reports that the EndpointSlice enumeration was
// exhaustive.
//
// The same contract as AttrPodSetComplete, and the same prohibition on universal
// claims when it is false.
const AttrSliceSetComplete domain.AttributeKey = "k8s.slice_set_complete"

// AttrSliceCount is how many associated EndpointSlices were admitted.
const AttrSliceCount domain.AttributeKey = "k8s.slice_count"

// AttrEndpointCount is how many distinct endpoints those slices published.
//
// Deduplicated by `targetRef` where present and by (addressType, address, port)
// otherwise, because an endpoint may legitimately appear in more than one slice
// and dual-stack guarantees separate slices per family. A count that
// double-counted a dual-stack backend would be a number nobody could reconcile
// with `kubectl` (ADR 0094 section 9.6).
//
// **No address, hostname, node name, zone or targetRef name is recorded** — only
// how many there were.
const AttrEndpointCount domain.AttributeKey = "k8s.endpoint_count"

// AttrReadyEndpointCount is how many of those endpoints are effective-ready.
//
// Effective-ready is decided by `conditions.ready` alone, with nil read as true.
// It consults no `serving`, no `terminating`, no targetRef, no address and no
// Pod: `ready` already *is* Kubernetes' shortcut for "serving and not
// terminating", and re-deriving it would silently change meaning for a Service
// with `publishNotReadyAddresses: true` (ADR 0094 section 2.6).
const AttrReadyEndpointCount domain.AttributeKey = "k8s.ready_endpoint_count"

// AttrTerminatingEndpointCount is how many endpoints report `terminating: true`.
//
// **Disclosure, not health.** A `serving=true, ready=false, terminating=true`
// endpoint is not dead, and Service proxies may still route to such endpoints
// when every available endpoint is terminating. This count exists so that "no
// ready endpoint" is not read as "nothing is serving", and no rule may turn it
// into a health inference.
//
// `terminating` is stable only from Kubernetes v1.26 while the supported floor
// is v1.21, so on an older server the field is simply absent and this count is
// zero by the frozen nil semantics.
const AttrTerminatingEndpointCount domain.AttributeKey = "k8s.terminating_endpoint_count"

// AttrSliceExcludedByOwnerUIDCount is how many labelled slices were excluded
// because their Service owner reference named a different UID.
//
// It makes the delete-and-recreate race guard auditable. A Service may be
// deleted and recreated between the GET and the LIST, and association by the
// `kubernetes.io/service-name` label is name-based and would silently cross
// generations. The owner reference carries the UID, so the guard costs no fourth
// API call — and the *count* of what it excluded is recorded while the UID
// itself never enters evidence (ADR 0094 section 2.4).
const AttrSliceExcludedByOwnerUIDCount domain.AttributeKey = "k8s.slice_excluded_by_owner_uid_count"

// AttrSliceExternallyManaged reports that at least one admitted slice is managed
// by something other than the built-in endpoint slice controller.
//
// `endpointslice.kubernetes.io/managed-by` does **not** gate admission: a
// third-party-managed slice carrying the authoritative Service association is a
// published backend, and excluding it would make svcdoctor disagree with
// kube-proxy. This records the fact a reader needs in order to interpret the
// answer, and it is a boolean rather than the manager's name because the name is
// operator-controlled text.
const AttrSliceExternallyManaged domain.AttributeKey = "k8s.slice_externally_managed"

// The authentication modes AttrAuthMode may hold.
//
// Exactly four, frozen by ADR 0094 section 2.3. Everything else is refused
// before any network operation: exec credential plugins, auth-provider of any
// name, anonymous access, basic authentication and every cloud plugin.
const (
	// AuthModeToken is a bearer token svcdoctor resolved and holds as a secret —
	// from the target's own credential reference, or written inline in the
	// selected kubeconfig user.
	AuthModeToken = "TOKEN"

	// AuthModeTokenFile is a bearer token read from a kubeconfig `tokenFile`.
	//
	// **svcdoctor reads the file, never client-go.** rest.Config.BearerTokenFile
	// is deliberately unused, because it would let the library read a secret
	// svcdoctor never masked and never bounded.
	AuthModeTokenFile = "TOKEN_FILE"

	// AuthModeClientCert is a client certificate and private key.
	//
	// The private key is secret material and travels as a security.Secret; the
	// certificate and the CA bundle are public and do not. This mode exists
	// because `kind` and `kubeadm` kubeconfigs authenticate this way, and
	// refusing it would make real-cluster validation unachievable.
	AuthModeClientCert = "CLIENT_CERT"

	// AuthModeInCluster is the projected ServiceAccount token.
	//
	// Selected explicitly, mutually exclusive with kubeconfig, and never a
	// fallback: a mounted ServiceAccount token must never cause svcdoctor to
	// acquire an identity nobody asked for.
	AuthModeInCluster = "IN_CLUSTER"
)

// The Service types AttrServiceType may hold.
//
// The four the Kubernetes API defines, plus svcdoctor's own value for one it
// does not recognize. A future or hostile `spec.type` becomes
// ServiceTypeUnknown, which is treated as unsupported for backend publication —
// an unrecognized value never unlocks behaviour.
const (
	ServiceTypeClusterIP    = "ClusterIP"
	ServiceTypeNodePort     = "NodePort"
	ServiceTypeLoadBalancer = "LoadBalancer"
	ServiceTypeExternalName = "ExternalName"
	ServiceTypeUnknown      = "UNKNOWN"
)

// ServiceID is the value domain.RunMetadata carries for a Kubernetes run.
const ServiceID = "kubernetes"
