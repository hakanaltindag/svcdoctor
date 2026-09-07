package kubernetes_test

import (
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// The Kubernetes rule fixtures.
//
// # Why the graph is built here rather than driven through the adapter
//
// Two reasons, and the second is the load-bearing one.
//
// A rule reads a frozen graph and nothing else, so a graph is the whole of its
// input and building one directly is the smallest honest test. And these tests
// must reach shapes the current adapter cannot produce — a Pod-set node carrying
// a count with no completeness flag, a Service node with an unrecognized type, a
// graph holding two Service nodes — because "the rule fails closed on a shape
// nobody makes today" is exactly the property that stops being true when
// somebody makes it.
//
// The complementary direction is proven elsewhere: `test/diagnosis` drives the
// real `adapter/kubernetes.Record` over synthetic acquisition results, so the
// rules are also tested against graphs the producer really emits.

const (
	fixtureNamespace = "payments"
	fixtureService   = "payments-api"
	fixtureSubject   = "service/" + fixtureNamespace + "/" + fixtureService
)

var fixtureStart = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// node is one evidence node's declared shape.
type node struct {
	step         domain.Step
	layer        domain.Layer
	state        domain.State
	failureClass domain.FailureClass
	attributes   map[domain.AttributeKey]domain.AttrValue
	// omit drops the node from the graph entirely, which is a shape no producer
	// makes and which every rule must tolerate.
	omit bool
	// blockedBy names the node that stopped this one, for a SKIPPED node.
	blockedBy domain.Step
}

// graphSpec is one run's five nodes.
//
// It starts as the shape a successful, ordinary run produces and each test
// changes only what it is about, so a failing assertion names one difference
// rather than a whole document.
type graphSpec struct {
	subject string

	target      node
	apiAccess   node
	service     node
	podSet      node
	publication node
}

// healthy is a run that read everything and found a Service with backends.
//
// One Pod, one slice, one endpoint, ready. It produces no Kubernetes finding at
// all, which is what most of the negative tests assert against.
func healthy() graphSpec {
	return graphSpec{
		subject: fixtureSubject,
		target: node{
			step: servicekubernetes.StepTarget, layer: domain.LayerInput,
			state: domain.StatePass, failureClass: domain.FailureNone,
		},
		apiAccess: node{
			step: servicekubernetes.StepAPIAccess, layer: domain.LayerAuth,
			state: domain.StatePass, failureClass: domain.FailureNone,
			attributes: map[domain.AttributeKey]domain.AttrValue{
				servicekubernetes.AttrAuthMode: domain.StringAttr(
					servicekubernetes.AuthModeToken),
			},
		},
		service:     serviceNode(servicekubernetes.ServiceTypeClusterIP, true, 2),
		podSet:      podSetNode(true, 3),
		publication: publicationNode(publicationCounts{slices: 1, endpoints: 1, ready: 1}),
	}
}

// serviceNode is a Service node that was read successfully.
func serviceNode(serviceType string, selectorPresent bool, selectorKeys int64) node {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		servicekubernetes.AttrNamespace:   domain.IdentityAttr(fixtureNamespace),
		servicekubernetes.AttrServiceName: domain.IdentityAttr(fixtureService),
		servicekubernetes.AttrServiceType: domain.StringAttr(serviceType),
		servicekubernetes.AttrServiceHeadless: domain.BoolAttr(
			serviceType == servicekubernetes.ServiceTypeClusterIP && selectorKeys == 0),
		servicekubernetes.AttrSelectorPresent:  domain.BoolAttr(selectorPresent),
		servicekubernetes.AttrSelectorKeyCount: domain.IntAttr(selectorKeys),
	}
	return node{
		step: servicekubernetes.StepService, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: attributes,
	}
}

// podSetNode is a Pod enumeration that ran to completion.
func podSetNode(complete bool, observed int64) node {
	state := domain.StatePass
	class := domain.FailureNone
	if !complete {
		// The shape the adapter produces when its own ceiling stopped the
		// expansion: UNKNOWN with a depth-limit class, never an empty set.
		state = domain.StateUnknown
		class = domain.FailureExecDepthLimit
	}
	return node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: state, failureClass: class,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrPodSetComplete:   domain.BoolAttr(complete),
			servicekubernetes.AttrPodObservedCount: domain.IntAttr(observed),
		},
	}
}

// publicationCounts is one EndpointSlice enumeration's six numbers.
type publicationCounts struct {
	slices      int64
	endpoints   int64
	ready       int64
	terminating int64
	excluded    int64
	incomplete  bool
	external    bool
}

// publicationNode is an EndpointSlice enumeration.
func publicationNode(counts publicationCounts) node {
	state := domain.StatePass
	class := domain.FailureNone
	if counts.incomplete {
		state = domain.StateUnknown
		class = domain.FailureExecDepthLimit
	}
	attributes := map[domain.AttributeKey]domain.AttrValue{
		servicekubernetes.AttrSliceSetComplete: domain.BoolAttr(!counts.incomplete),
		servicekubernetes.AttrSliceCount:       domain.IntAttr(counts.slices),
		servicekubernetes.AttrEndpointCount:    domain.IntAttr(counts.endpoints),
		servicekubernetes.AttrReadyEndpointCount: domain.IntAttr(
			counts.ready),
		servicekubernetes.AttrTerminatingEndpointCount: domain.IntAttr(counts.terminating),
		servicekubernetes.AttrSliceExcludedByOwnerUIDCount: domain.IntAttr(
			counts.excluded),
	}
	if counts.external {
		attributes[servicekubernetes.AttrSliceExternallyManaged] = domain.BoolAttr(true)
	}
	return node{
		step: servicekubernetes.StepEndpointPublication, layer: domain.LayerTopology,
		state: state, failureClass: class, attributes: attributes,
	}
}

// skipped is a stage that never ran.
//
// It carries **no attribute at all**, which is what the adapter produces: a read
// that was not issued observed nothing, and a completeness flag or a count on
// such a node would be a measurement nobody took.
func skipped(step domain.Step, class domain.FailureClass, blockedBy domain.Step) node {
	return node{
		step: step, layer: domain.LayerTopology,
		state: domain.StateSkipped, failureClass: class, blockedBy: blockedBy,
	}
}

// denied is a read the API server refused with a 403.
//
// UNKNOWN with AUTHZ_NOT_PERMITTED is the exact pair the adapter maps
// `apierrors.IsForbidden` to, and it maps nothing else to it. Like a skipped
// node it carries no counts, because the read produced none.
func denied(step domain.Step) node {
	return node{
		step: step, layer: domain.LayerTopology,
		state: domain.StateUnknown, failureClass: domain.FailureAuthzNotPermitted,
	}
}

// serviceNotFound is the Service node a 404 produces.
func serviceNotFound() node {
	return node{
		step: servicekubernetes.StepService, layer: domain.LayerTopology,
		state: domain.StateFail, failureClass: domain.FailureResourceNotFound,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrNamespace:   domain.IdentityAttr(fixtureNamespace),
			servicekubernetes.AttrServiceName: domain.IdentityAttr(fixtureService),
		},
	}
}

// nodes returns the five in journey order.
func (g graphSpec) nodes() []node {
	return []node{g.target, g.apiAccess, g.service, g.podSet, g.publication}
}

// build freezes the specification into a graph.
//
// insertion permutes the order nodes are added in, so that a test can prove the
// rules do not depend on it. The graph's own ordering is canonical, which is
// what makes the permutation safe to drive.
func (g graphSpec) build(t testing.TB, insertion []int) domain.Graph {
	t.Helper()

	subjectRef := g.subject
	if subjectRef == "" {
		subjectRef = fixtureSubject
	}
	subject, err := domain.NewTargetSubject(subjectRef)
	if err != nil {
		t.Fatalf("NewTargetSubject(%q): %v", subjectRef, err)
	}

	builder := domain.NewGraphBuilder()
	present := []node{}
	for _, n := range g.nodes() {
		if !n.omit {
			present = append(present, n)
		}
	}
	if insertion == nil {
		insertion = identityOrder(len(present))
	}
	if len(insertion) != len(present) {
		t.Fatalf("insertion order has %d entries for %d nodes", len(insertion), len(present))
	}

	ids := map[domain.Step]domain.EvidenceID{}
	for _, index := range insertion {
		n := present[index]
		elapsed := domain.Measured(time.Millisecond)
		if n.state == domain.StateSkipped || n.state == domain.StateUnknown {
			elapsed = domain.Unmeasured()
		}
		evidence, err := domain.NewEvidence(domain.EvidenceInput{
			ID:           evidenceIDFor(n.step, subjectRef),
			Subject:      subject,
			Layer:        n.layer,
			Step:         n.step,
			State:        n.state,
			FailureClass: n.failureClass,
			Attributes:   n.attributes,
			StartedAt:    fixtureStart,
			Elapsed:      elapsed,
		})
		if err != nil {
			t.Fatalf("NewEvidence(%s): %v", n.step, err)
		}
		if err := builder.AddEvidence(evidence); err != nil {
			t.Fatalf("AddEvidence(%s): %v", n.step, err)
		}
		ids[n.step] = evidence.ID()
	}

	// The edges, added after every node exists so that insertion order cannot
	// make a parent unresolvable.
	for _, n := range present {
		parent, ok := parentOf(n.step)
		if !ok {
			continue
		}
		parentID, exists := ids[parent]
		if !exists {
			continue
		}
		if err := builder.AddParent(ids[n.step], parentID); err != nil {
			t.Fatalf("AddParent(%s): %v", n.step, err)
		}
	}
	for _, n := range present {
		if n.state != domain.StateSkipped || n.blockedBy == "" {
			continue
		}
		blocker, exists := ids[n.blockedBy]
		if !exists {
			continue
		}
		if err := builder.AddBlockedBy(ids[n.step], blocker); err != nil {
			t.Fatalf("AddBlockedBy(%s): %v", n.step, err)
		}
	}

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// evidenceIDFor spells an identifier the way internal/probe does.
//
// It is spelled here rather than imported because `depguard`'s `diagnosis-is-
// pure` list refuses `internal/probe` from this package, tests included — and
// that refusal is right: a rule reads a frozen graph, and a fixture that could
// reach the probe layer would be one import away from a rule that could.
//
// Nothing depends on the spelling matching production byte for byte; a rule
// treats an identifier as opaque. `test/diagnosis` drives the real adapter,
// which is where the production spelling is exercised.
func evidenceIDFor(step domain.Step, label string) domain.EvidenceID {
	return domain.EvidenceID(string(step) + "/" + label)
}

// parentOf is the frozen journey, so the fixture cannot invent a shape.
func parentOf(step domain.Step) (domain.Step, bool) {
	switch step {
	case servicekubernetes.StepAPIAccess:
		return servicekubernetes.StepTarget, true
	case servicekubernetes.StepService:
		return servicekubernetes.StepAPIAccess, true
	case servicekubernetes.StepPodSet, servicekubernetes.StepEndpointPublication:
		return servicekubernetes.StepService, true
	default:
		return "", false
	}
}

// admissible reports whether domain.NewEvidence accepts a state and class
// together.
//
// The domain refuses PASS with a failure class and FAIL without one, which is a
// real invariant rather than a fixture limitation: a passing measurement has no
// failure to classify, and a failure with no class is one nobody named. The
// property tests generate the whole cross product and skip the pairs the model
// itself makes unrepresentable, so they stay exhaustive over what a producer
// could actually emit.
func admissible(state domain.State, class domain.FailureClass) bool {
	switch {
	case state == domain.StatePass && class != domain.FailureNone:
		return false
	case state == domain.StateFail && class == domain.FailureNone:
		return false
	default:
		return true
	}
}

func identityOrder(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// evaluate runs both Kubernetes rules over one specification.
//
// It runs **both**, always, because the phase's coexistence and disjointness
// properties are about what the pair produces together, and a test that ran one
// rule could not see either.
func (g graphSpec) evaluate(t testing.TB) []domain.Finding {
	t.Helper()
	return evaluateGraph(t, g.build(t, nil))
}

func evaluateGraph(t testing.TB, graph domain.Graph) []domain.Finding {
	t.Helper()

	ctx := diagnosis.RuleContext{Graph: graph}
	var out []domain.Finding
	for _, rule := range productionRules() {
		out = append(out, rule.eval(ctx)...)
	}
	return out
}

// codesOf reduces findings to the codes they carry, in production order.
func codesOf(findings []domain.Finding) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Code())
	}
	return out
}

// hasCode reports whether the set carries one code.
func hasCode(findings []domain.Finding, code domain.FindingCode) bool {
	for _, finding := range findings {
		if finding.Code() == code {
			return true
		}
	}
	return false
}

// findingsWithCode returns every finding carrying one code.
func findingsWithCode(findings []domain.Finding, code domain.FindingCode) []domain.Finding {
	var out []domain.Finding
	for _, finding := range findings {
		if finding.Code() == code {
			out = append(out, finding)
		}
	}
	return out
}

// only asserts the exact code multiset a scenario produces.
func only(t testing.TB, findings []domain.Finding, want ...domain.FindingCode) {
	t.Helper()

	got := codesOf(findings)
	if len(got) != len(want) {
		t.Fatalf("produced %v, want exactly %v", got, want)
	}
	counts := map[domain.FindingCode]int{}
	for _, code := range got {
		counts[code]++
	}
	for _, code := range want {
		counts[code]--
	}
	for code, remaining := range counts {
		if remaining != 0 {
			t.Fatalf("produced %v, want exactly %v (%s differs)", got, want, code)
		}
	}
}
