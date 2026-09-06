package kubernetes

import (
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes/client"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// Record writes one acquisition's five evidence nodes and the edges between
// them.
//
// It returns the identifier of the target anchor, so a caller that wants to hang
// anything else off the run has a root to name — and, today, so a test can
// assert the shape without parsing identifiers.
//
// # Every node is written, always
//
// A run that failed at the first request still records five nodes: one PASS
// anchor, one failed api_access, and three SKIPPED nodes each carrying a
// blocked-by edge to what stopped them. A graph whose shape changed with the
// outcome would make "the slice read did not happen" indistinguishable from "the
// slice read was never part of this run".
func Record(
	builder *domain.GraphBuilder, result client.Result, startedAt time.Time,
) (domain.EvidenceID, error) {
	subject, err := domain.NewTargetSubject(result.Target.SubjectRef())
	if err != nil {
		return "", fmt.Errorf("building the Kubernetes subject: %w", err)
	}
	label := result.Target.SubjectRef()

	target, err := recordTarget(builder, subject, label, result, startedAt)
	if err != nil {
		return "", err
	}
	access, err := recordAPIAccess(builder, subject, label, result, startedAt, target)
	if err != nil {
		return "", err
	}
	service, err := recordService(builder, subject, label, result, startedAt, access)
	if err != nil {
		return "", err
	}
	if err := recordPodSet(builder, subject, label, result, startedAt, service, access); err != nil {
		return "", err
	}
	if err := recordPublication(
		builder, subject, label, result, startedAt, service, access,
	); err != nil {
		return "", err
	}
	return target, nil
}

// recordTarget writes the one node that is not a measurement.
//
// It claims that input normalization accepted this namespace and Service name,
// and nothing else. It does not claim that the Service exists, that the API
// server is reachable, that a credential works, or that anything is healthy.
//
// It is always PASS, for the reason the transport anchor always is: unusable
// input is refused before a graph exists, so there is no FAIL form of it.
//
// # Why it carries no attributes
//
// The subject is the Service, and ADR 0094 §11.1's frozen table places
// `k8s.namespace` and `k8s.service_name` on the `k8s.service` node rather than
// here. That agrees with the transport anchor's own discipline: ADR 0042 §6 gives
// `target.requested` no attributes because each would be a second copy of
// something the subject already states.
//
// **This node carried the two identity attributes until the Phase 12.1B review
// pass**, which reconciled the implementation to the frozen table. The keys and
// their values are unchanged; only the node they hang on is.
func recordTarget(
	builder *domain.GraphBuilder, subject domain.Subject, label string,
	_ client.Result, at time.Time,
) (domain.EvidenceID, error) {
	return add(builder, domain.EvidenceInput{
		ID:      probe.EvidenceID(servicekubernetes.StepTarget, label),
		Subject: subject,
		Layer:   domain.LayerInput,
		Step:    servicekubernetes.StepTarget,
		State:   domain.StatePass,
		// Explicit rather than left to the zero value, so a reader does not have
		// to know that FailureNone is the zero FailureClass to see that this node
		// asserts no failure.
		FailureClass: domain.FailureNone,
		StartedAt:    at,
		// Asking is not an operation with a duration.
		Elapsed: domain.Unmeasured(),
	})
}

// recordAPIAccess writes what the API server made of this run's identity.
//
// The attributes are the authority facts a reader needs to reconstruct under
// what authority the report was produced: the **category** of credential, and
// the operator's context choice. A token, a private key, a certificate, a
// credential path, a kubeconfig path and a proxy URL are all absent — and there
// is no AttrValue constructor that could carry any of them, which makes most of
// that structural rather than a rule.
func recordAPIAccess(
	builder *domain.GraphBuilder, subject domain.Subject, label string,
	result client.Result, at time.Time, parent domain.EvidenceID,
) (domain.EvidenceID, error) {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		servicekubernetes.AttrAuthMode: domain.StringAttr(result.Authority.Mode),
	}
	// Absent in-cluster rather than empty. There is no context there, and
	// recording an empty one would say a choice was made that was not.
	if result.Authority.Context != "" {
		attributes[servicekubernetes.AttrContext] =
			domain.IdentityAttr(result.Authority.Context)
	}

	state, class := stageState(result.APIAccess)
	id, err := add(builder, domain.EvidenceInput{
		ID:           probe.EvidenceID(servicekubernetes.StepAPIAccess, label),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         servicekubernetes.StepAPIAccess,
		State:        state,
		FailureClass: class,
		Attributes:   attributes,
		StartedAt:    startOf(result.APIAccess.StartedAt, at),
		Elapsed:      elapsedOf(result.APIAccess.Attempted, result.APIAccess.Elapsed),
	})
	if err != nil {
		return "", err
	}
	if err := link(builder, id, parent, state, parent); err != nil {
		return "", err
	}
	return id, nil
}

// recordService writes the GET's outcome and the Service's shape.
//
// # Two kinds of attribute, and only one of them is an observation
//
// The namespace and the Service name are **inputs**: they came from the target's
// own declaration, they are true whether or not the read succeeded, and ADR 0094
// §11.1's frozen table places them on this node. They are recorded
// unconditionally for exactly that reason — a run whose Service read was denied
// is the run whose reader most needs to see what was asked for, and a consumer
// must not have to parse a subject reference to recover it.
//
// The four Service facts are **observations** and are recorded only when the read
// succeeded. A node that did not obtain a Service carries no claim about its
// type, its selector or whether it is headless, because there is nothing to have
// observed.
func recordService(
	builder *domain.GraphBuilder, subject domain.Subject, label string,
	result client.Result, at time.Time, parent domain.EvidenceID,
) (domain.EvidenceID, error) {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		servicekubernetes.AttrNamespace:   domain.IdentityAttr(result.Target.Namespace),
		servicekubernetes.AttrServiceName: domain.IdentityAttr(result.Target.ServiceName),
	}
	if result.Service.OK() {
		facts := result.ServiceFacts
		attributes[servicekubernetes.AttrServiceType] = domain.StringAttr(facts.Type)
		attributes[servicekubernetes.AttrServiceHeadless] = domain.BoolAttr(facts.Headless)
		attributes[servicekubernetes.AttrSelectorPresent] =
			domain.BoolAttr(facts.SelectorPresent)
		attributes[servicekubernetes.AttrSelectorKeyCount] =
			domain.IntAttr(int64(facts.SelectorKeyCount))
	}

	state, class := stageState(result.Service)
	id, err := add(builder, domain.EvidenceInput{
		ID:           probe.EvidenceID(servicekubernetes.StepService, label),
		Subject:      subject,
		Layer:        domain.LayerTopology,
		Step:         servicekubernetes.StepService,
		State:        state,
		FailureClass: class,
		Attributes:   attributes,
		StartedAt:    startOf(result.Service.StartedAt, at),
		Elapsed:      elapsedOf(result.Service.Attempted, result.Service.Elapsed),
	})
	if err != nil {
		return "", err
	}
	if err := link(builder, id, parent, state, parent); err != nil {
		return "", err
	}
	return id, nil
}

// recordPodSet writes the Pod enumeration as a set, never as Pods.
//
// Two attributes, and the second is meaningless without the first: a count is a
// total only when the enumeration was exhaustive. They are always recorded
// together for exactly that reason, so a consumer cannot read one without the
// other being present.
func recordPodSet(
	builder *domain.GraphBuilder, subject domain.Subject, label string,
	result client.Result, at time.Time, parent, access domain.EvidenceID,
) error {
	state, class := enumerationState(result.Pods)
	attributes := map[domain.AttributeKey]domain.AttrValue{}
	if result.Pods.Attempted {
		attributes[servicekubernetes.AttrPodSetComplete] =
			domain.BoolAttr(result.Pods.Complete())
		attributes[servicekubernetes.AttrPodObservedCount] =
			domain.IntAttr(int64(result.Pods.Observed))
	}

	id, err := add(builder, domain.EvidenceInput{
		ID:           probe.EvidenceID(servicekubernetes.StepPodSet, label),
		Subject:      subject,
		Layer:        domain.LayerTopology,
		Step:         servicekubernetes.StepPodSet,
		State:        state,
		FailureClass: class,
		Attributes:   attributes,
		StartedAt:    startOf(result.Pods.StartedAt, at),
		Elapsed:      elapsedOf(result.Pods.Attempted, result.Pods.Elapsed),
	})
	if err != nil {
		return err
	}
	return link(builder, id, parent, state, blockerFor(result.Pods.Skip, parent, access))
}

// recordPublication writes the EndpointSlice enumeration as a publication.
//
// Six facts, all counts and one boolean. **No address, hostname, zone, node
// name, targetRef name or slice name**, because no admitted finding consumes one
// and every one of them is identity belonging to the cluster rather than to the
// question being asked.
func recordPublication(
	builder *domain.GraphBuilder, subject domain.Subject, label string,
	result client.Result, at time.Time, parent, access domain.EvidenceID,
) error {
	state, class := enumerationState(result.Publication)
	attributes := map[domain.AttributeKey]domain.AttrValue{}
	if result.Publication.Attempted {
		facts := result.PublicationFacts
		attributes[servicekubernetes.AttrSliceSetComplete] =
			domain.BoolAttr(result.Publication.Complete())
		attributes[servicekubernetes.AttrSliceCount] = domain.IntAttr(int64(facts.Slices))
		attributes[servicekubernetes.AttrEndpointCount] =
			domain.IntAttr(int64(facts.Endpoints))
		attributes[servicekubernetes.AttrReadyEndpointCount] =
			domain.IntAttr(int64(facts.ReadyEndpoints))
		attributes[servicekubernetes.AttrTerminatingEndpointCount] =
			domain.IntAttr(int64(facts.TerminatingEndpoints))
		attributes[servicekubernetes.AttrSliceExcludedByOwnerUIDCount] =
			domain.IntAttr(int64(facts.ExcludedByOwnerUID))
		// Recorded only when true, because "no third party manages these slices"
		// is the ordinary case and a false on every report would be noise a
		// reader learns to skip.
		if facts.ExternallyManaged {
			attributes[servicekubernetes.AttrSliceExternallyManaged] = domain.BoolAttr(true)
		}
	}

	id, err := add(builder, domain.EvidenceInput{
		ID:           probe.EvidenceID(servicekubernetes.StepEndpointPublication, label),
		Subject:      subject,
		Layer:        domain.LayerTopology,
		Step:         servicekubernetes.StepEndpointPublication,
		State:        state,
		FailureClass: class,
		Attributes:   attributes,
		StartedAt:    startOf(result.Publication.StartedAt, at),
		Elapsed:      elapsedOf(result.Publication.Attempted, result.Publication.Elapsed),
	})
	if err != nil {
		return err
	}
	return link(builder, id, parent, state, blockerFor(result.Publication.Skip, parent, access))
}

// stageState maps one acquisition stage onto a state and a failure class.
//
// # The mapping is closed, and the FAIL/UNKNOWN split is the load-bearing part
//
// **FAIL means the peer answered and the answer is a fact about the target.** A
// 401 and a 404 are answers. **UNKNOWN means svcdoctor did not obtain the
// answer**, and a denied read is deliberately on that side: a 403 says the
// measurement was not made, not that the thing measured is absent. Collapsing
// the two would let "svcdoctor was not allowed to look" become "there is nothing
// there", which is the single worst mistake this contract exists to prevent.
func stageState(stage client.Stage) (domain.State, domain.FailureClass) {
	if !stage.Attempted {
		return domain.StateSkipped, skipClass(stage.Skip)
	}
	return failureState(stage.Failure)
}

// enumerationState maps one enumeration onto a state and a failure class.
//
// An enumeration that ran and stopped short is UNKNOWN rather than FAIL: the set
// is incomplete, which is a statement about the measurement and not about the
// target. An enumeration that completed is PASS whatever its count was, because
// an empty complete set is a successful measurement of an empty set.
func enumerationState(enumeration client.Enumeration) (domain.State, domain.FailureClass) {
	if !enumeration.Attempted {
		return domain.StateSkipped, skipClass(enumeration.Skip)
	}
	if enumeration.Failure != client.FailureNone {
		return failureState(enumeration.Failure)
	}
	switch enumeration.Stop {
	case client.StopComplete:
		return domain.StatePass, domain.FailureNone
	case client.StopPageLimit, client.StopObjectLimit, client.StopEndpointLimit:
		// svcdoctor's own bound stopped the expansion. It is not a target
		// failure and it is not an empty set; it is a measurement that did not
		// finish, and exit code 4 is what says so.
		return domain.StateUnknown, domain.FailureExecDepthLimit
	case client.StopCancelled:
		return domain.StateUnknown, domain.FailureExecCancelled
	default:
		return domain.StateUnknown, domain.FailureProtocolUnexpectedResponse
	}
}

// failureState maps the client's closed failure vocabulary onto the domain's.
//
// It is a total function over client.Failure. A value it does not recognize
// becomes UNKNOWN with an unexpected-response class, which claims nothing about
// the target — an unrecognized failure never produces a stronger state.
func failureState(failure client.Failure) (domain.State, domain.FailureClass) {
	switch failure {
	case client.FailureNone:
		return domain.StatePass, domain.FailureNone
	case client.FailureUnauthorized:
		return domain.StateFail, domain.FailureAuthCredentialsRejected
	case client.FailureForbidden:
		// UNKNOWN, not FAIL. The target did not fail; svcdoctor's measurement was
		// blocked, and every universal claim over the set it would have produced
		// is withheld.
		return domain.StateUnknown, domain.FailureAuthzNotPermitted
	case client.FailureNotFound:
		return domain.StateFail, domain.FailureResourceNotFound
	case client.FailureResourceExpired, client.FailureAPIError:
		return domain.StateUnknown, domain.FailureProtocolUnexpectedResponse
	case client.FailureTransport:
		return domain.StateFail, domain.FailureTCPConnectionFailed
	case client.FailureTLSUnknownAuthority:
		return domain.StateFail, domain.FailureTLSUnknownAuthority
	case client.FailureTLSHostnameMismatch:
		return domain.StateFail, domain.FailureTLSHostnameMismatch
	case client.FailureTLSCertificateExpired:
		return domain.StateFail, domain.FailureTLSCertificateExpired
	case client.FailureTimeout:
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	case client.FailureCancelled:
		return domain.StateUnknown, domain.FailureExecCancelled
	default:
		return domain.StateUnknown, domain.FailureProtocolUnexpectedResponse
	}
}

// skipClass explains a stage that did not run.
//
// A selector-less or unsupported Service is **not** a prerequisite failure:
// nothing failed, and there was simply nothing of that kind to measure. It is
// recorded as unsupported-by-svcdoctor, which is the class whose own definition
// is *"svcdoctor cannot check this; a gap in the tool, not a defect in the
// target"* — and that is exactly true here.
func skipClass(reason client.SkipReason) domain.FailureClass {
	switch reason {
	case client.SkipSelectorLess, client.SkipUnsupportedServiceType:
		return domain.FailureExecUnsupportedBySvcdoctor
	case client.SkipCancelled:
		return domain.FailureExecCancelled
	default:
		return domain.FailureExecSkippedPrerequisiteFailed
	}
}

// blockerFor names what stopped a skipped stage.
//
// A stage the API access failure stopped is blocked by the api_access node; a
// stage the Service read stopped, and a stage svcdoctor declined to run because
// of the Service's own shape, are blocked by the Service node. The edge is
// recorded rather than inferred, which is why the caller passes both candidates
// in.
func blockerFor(reason client.SkipReason, service, access domain.EvidenceID) domain.EvidenceID {
	if reason == client.SkipAPIAccessFailed {
		return access
	}
	return service
}

// link records the parent edge, and the blocked-by edge when there is one.
//
// A blocked-by reference is only legal on a SKIPPED node, and it says something a
// parent edge does not: the parent is where this node sits in the journey, and
// the blocker is why it never happened.
func link(
	builder *domain.GraphBuilder, id, parent domain.EvidenceID,
	state domain.State, blocker domain.EvidenceID,
) error {
	if err := builder.AddParent(id, parent); err != nil {
		return fmt.Errorf("recording the parent of %s: %w", id, err)
	}
	if state != domain.StateSkipped || blocker == "" || blocker == id {
		return nil
	}
	if err := builder.AddBlockedBy(id, blocker); err != nil {
		return fmt.Errorf("recording what blocked %s: %w", id, err)
	}
	return nil
}

func add(builder *domain.GraphBuilder, in domain.EvidenceInput) (domain.EvidenceID, error) {
	evidence, err := domain.NewEvidence(in)
	if err != nil {
		return "", fmt.Errorf("building %s evidence: %w", in.Step, err)
	}
	if err := builder.AddEvidence(evidence); err != nil {
		return "", fmt.Errorf("recording %s evidence: %w", in.Step, err)
	}
	return evidence.ID(), nil
}

// startOf falls back to the run's own start for a stage that never began.
//
// Evidence requires a start time, and a node for a stage that was skipped has no
// measurement window of its own. Using the run's start says when the run that
// decided not to measure it began, which is the only true instant available.
func startOf(stageStart, runStart time.Time) time.Time {
	if stageStart.IsZero() {
		return runStart
	}
	return stageStart
}

// elapsedOf records a duration only for a stage that ran.
//
// A stage that never happened is Unmeasured rather than zero. Before the Elapsed
// type existed, both wrote a zero a reader could not tell from an instantaneous
// measurement.
func elapsedOf(attempted bool, elapsed time.Duration) domain.Elapsed {
	if !attempted {
		return domain.Unmeasured()
	}
	return domain.Measured(elapsed)
}
