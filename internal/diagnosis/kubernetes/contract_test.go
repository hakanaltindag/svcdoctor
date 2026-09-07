package kubernetes_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// The frozen field contract, one row per code.
//
// Every value here is ADR 0094 section 2.7's and PHASE121A section 10.3's, and
// none of them is derivable from anything else in the tree — which is why they
// are written out rather than computed. A change to any of them is a change to
// what svcdoctor publishes about somebody's cluster.
type contract struct {
	kind             domain.FindingKind
	severity         domain.Severity
	confidence       domain.Confidence
	layer            domain.Layer
	vantageDependent bool
	discriminator    string
	recommendations  int
	safety           domain.SafetyClass
	adviceKind       domain.RecommendationKind
	selfCollectable  bool
}

func frozenContracts() map[domain.FindingCode]contract {
	confirmed := domain.FindingKindConfirmed
	return map[domain.FindingCode]contract{
		f1: {
			kind: confirmed, severity: domain.SeverityError,
			confidence: domain.ConfidenceHigh, layer: domain.LayerTopology,
			vantageDependent: false, discriminator: "", recommendations: 1,
			safety: diagnosis.SafetyVerify, adviceKind: diagnosis.AdviceKindNextEvidence,
			selfCollectable: false,
		},
		f2: {
			// WARN, not ERROR: the target did not fail, svcdoctor's measurement
			// was blocked. The node's own state is UNKNOWN for the same reason.
			kind: confirmed, severity: domain.SeverityWarn,
			confidence: domain.ConfidenceHigh, layer: domain.LayerTopology,
			vantageDependent: false, discriminator: "", recommendations: 1,
			safety: diagnosis.SafetyVerify, adviceKind: diagnosis.AdviceKindNextEvidence,
			selfCollectable: false,
		},
		f3: {
			kind: confirmed, severity: domain.SeverityError,
			confidence: domain.ConfidenceHigh, layer: domain.LayerTopology,
			vantageDependent: false, discriminator: "", recommendations: 1,
			safety: diagnosis.SafetyCompare, adviceKind: diagnosis.AdviceKindNextEvidence,
			selfCollectable: false,
		},
		f4: {
			kind: confirmed, severity: domain.SeverityError,
			confidence: domain.ConfidenceHigh, layer: domain.LayerTopology,
			vantageDependent: false, discriminator: "", recommendations: 1,
			safety: diagnosis.SafetyCompare, adviceKind: diagnosis.AdviceKindNextEvidence,
			selfCollectable: false,
		},
	}
}

// TestEveryProducedFindingMatchesItsFrozenContract drives the whole matrix.
//
// It is the assertion that would fail first if a severity, a confidence, a kind,
// a layer or a recommendation's safety class drifted — none of which any other
// test in this package looks at directly.
func TestEveryProducedFindingMatchesItsFrozenContract(t *testing.T) {
	contracts := frozenContracts()
	seen := map[domain.FindingCode]int{}

	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			want, frozen := contracts[finding.Code()]
			if !frozen {
				t.Fatalf("%s produced %s, which has no frozen contract",
					name, finding.Code())
			}
			seen[finding.Code()]++
			assertContract(t, name, finding, want)
		}
	}

	for code := range contracts {
		if seen[code] == 0 {
			t.Errorf("%s is never produced by any scenario; its contract row is "+
				"vacuous", code)
		}
	}
}

func assertContract(t *testing.T, scenario string, finding domain.Finding, want contract) {
	t.Helper()

	label := scenario + "/" + string(finding.Code())
	if got := finding.Kind(); got != want.kind {
		t.Errorf("%s: kind is %s, want %s.\n\n"+
			"All four are CONFIRMED. Each restates what an authoritative source stated, "+
			"and no hypothesis is created merely because Kubernetes is eventually "+
			"consistent: eventual consistency bounds a claim's scope, not its kind "+
			"(ADR 0094 section 2.7).", label, got, want.kind)
	}
	if got := finding.Severity(); got != want.severity {
		t.Errorf("%s: severity is %s, want %s", label, got, want.severity)
	}
	if got := finding.Confidence(); got != want.confidence {
		t.Errorf("%s: confidence is %s, want %s", label, got, want.confidence)
	}
	if got := finding.Layer(); got != want.layer {
		t.Errorf("%s: layer is %s, want %s.\n\n"+
			"ADR 0094 section 2.9 puts every read at L6, and each claim takes its layer "+
			"from the node it cites so the two can never disagree.", label, got, want.layer)
	}
	if got := finding.VantageDependent(); got != want.vantageDependent {
		t.Errorf("%s: vantageDependent is %v, want %v.\n\n"+
			"What an API server answers does not depend on where it was asked from. "+
			"Whether the published endpoints can be *reached* from here would — and that "+
			"is the claim these findings refuse to make.", label, got, want.vantageDependent)
	}
	if got := finding.Discriminator(); got != want.discriminator {
		t.Errorf("%s: discriminator is %q, want %q; none of the four carries one",
			label, got, want.discriminator)
	}

	recommendations := finding.Recommendations()
	if len(recommendations) != want.recommendations {
		t.Fatalf("%s: %d recommendations, want %d",
			label, len(recommendations), want.recommendations)
	}
	for _, recommendation := range recommendations {
		if got := recommendation.Kind(); got != want.adviceKind {
			t.Errorf("%s: recommendation kind is %s, want %s.\n\n"+
				"Recommendations are NEXT_EVIDENCE only (ADR 0094 section 2.7). "+
				"svcdoctor changes nothing about a cluster and suggests no change to one.",
				label, got, want.adviceKind)
		}
		if got := recommendation.Safety(); got != want.safety {
			t.Errorf("%s: safety class is %s, want %s", label, got, want.safety)
		}
		if got := recommendation.SelfCollectable(); got != want.selfCollectable {
			t.Errorf("%s: selfCollectable is %v, want %v.\n\n"+
				"svcdoctor reads three objects through three bounded requests and holds "+
				"no model of what a cluster was meant to contain, so no differently "+
				"configured run could take any of these observations for the operator.",
				label, got, want.selfCollectable)
		}
		if strings.TrimSpace(recommendation.Rationale()) == "" {
			t.Errorf("%s: the recommendation states no rationale; a suggestion with no "+
				"stated reason cannot be reviewed or rejected", label)
		}
		if err := diagnosis.ValidateActionText(recommendation.Action()); err != nil {
			t.Errorf("%s: the recommendation is not safe action text: %v", label, err)
		}
	}
}

// TestNoKubernetesRecommendationIsEverARemediation.
//
// This is the property `diagnosis.NewAdvice` already enforces on the
// construction path, asserted from the outside so that a rule which stopped
// using that path would still be caught. The three high-blast-radius classes are
// the ones ADR 0092 section 2.8 makes unreachable, and RESTART and CONFIG_CHANGE
// are the two a Kubernetes rule would be most tempted by.
func TestNoKubernetesRecommendationIsEverARemediation(t *testing.T) {
	produced := 0
	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			for _, recommendation := range finding.Recommendations() {
				produced++
				if recommendation.Kind() == diagnosis.AdviceKindRemediation {
					t.Errorf("%s/%s recommends a change to make", name, finding.Code())
				}
				switch recommendation.Safety() {
				case diagnosis.SafetyObserve, diagnosis.SafetyVerify, diagnosis.SafetyCompare:
				default:
					t.Errorf("%s/%s carries a %s recommendation; the Kubernetes ceiling is "+
						"the three read-only classes", name, finding.Code(),
						recommendation.Safety())
				}
			}
		}
	}
	if produced == 0 {
		t.Fatal("no recommendation was produced at all; this guard would pass vacuously")
	}
}

// TestEveryFindingCitesExactlyTheFrozenEvidence.
//
// PHASE121A section 10.3 froze the membership node for node, and it is the
// minimal sufficient proof docs/FINDINGS.md section 3.1 rule 10 asks for: delete
// any cited node from the graph and the claim stops standing up.
//
// The over-citation direction matters as much as the under-citation one. A
// finding that cited the whole journey would look better supported than it is,
// and would make a reader who checks the references believe svcdoctor reasoned
// from facts it did not use.
func TestEveryFindingCitesExactlyTheFrozenEvidence(t *testing.T) {
	want := map[domain.FindingCode][]domain.Step{
		f1: {servicekubernetes.StepService},
		// F2's single node is whichever read was denied, so it is checked
		// separately below.
		f3: {servicekubernetes.StepService, servicekubernetes.StepPodSet},
		f4: {servicekubernetes.StepService, servicekubernetes.StepEndpointPublication},
	}

	checked := 0
	for name, spec := range everyScenario() {
		graph := spec.build(t, nil)
		for _, finding := range evaluateGraph(t, graph) {
			steps := stepsOf(t, graph, finding)
			if finding.Code() == f2 {
				if len(steps) != 1 {
					t.Errorf("%s: %s cites %v, want exactly one denied read",
						name, finding.Code(), steps)
				}
				checked++
				continue
			}
			expected := want[finding.Code()]
			if !sameSteps(steps, expected) {
				t.Errorf("%s: %s cites %v, want %v", name, finding.Code(), steps, expected)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no finding was checked; this guard would pass vacuously")
	}
}

// TestNoFindingCitesANodeThatIsNotAboutIt.
//
// The complement of the membership test, stated as a property rather than as a
// table: a claim about a Pod enumeration may not cite the EndpointSlice node and
// the reverse, because the two are siblings measuring different things and
// citing one for the other's claim would say svcdoctor reasoned across a branch
// it deliberately keeps independent.
func TestNoFindingCitesANodeThatIsNotAboutIt(t *testing.T) {
	forbidden := map[domain.FindingCode]map[domain.Step]bool{
		f1: {
			servicekubernetes.StepPodSet:              true,
			servicekubernetes.StepEndpointPublication: true,
		},
		f3: {servicekubernetes.StepEndpointPublication: true},
		f4: {servicekubernetes.StepPodSet: true},
	}

	for name, spec := range everyScenario() {
		graph := spec.build(t, nil)
		for _, finding := range evaluateGraph(t, graph) {
			banned := forbidden[finding.Code()]
			for _, step := range stepsOf(t, graph, finding) {
				if banned[step] {
					t.Errorf("%s: %s cites %s, which is a different branch's measurement",
						name, finding.Code(), step)
				}
			}
		}
	}
}

// TestEveryReferencedNodeResolvesInTheGraph is rule 12, checked here rather than
// only at report assembly.
//
// A rule must not knowingly produce a dangling reference, and catching it at the
// rule is what names the rule rather than the report.
func TestEveryReferencedNodeResolvesInTheGraph(t *testing.T) {
	for name, spec := range everyScenario() {
		graph := spec.build(t, nil)
		for _, finding := range evaluateGraph(t, graph) {
			if len(finding.EvidenceRefs()) == 0 {
				t.Errorf("%s: %s cites no evidence at all", name, finding.Code())
			}
			for _, ref := range finding.EvidenceRefs() {
				if _, ok := graph.Node(ref); !ok {
					t.Errorf("%s: %s cites %s, which is not in the graph",
						name, finding.Code(), ref)
				}
			}
		}
	}
}

// TestEveryFindingsSubjectIsTheServiceItself.
//
// One target is one Service, and the subject is `service/<ns>/<name>` at
// SubjectKindTarget for every node and therefore for every finding. A finding
// whose subject were an address or a Pod would be a claim under an identity
// svcdoctor deliberately never creates (ADR 0094 section 2.4).
func TestEveryFindingsSubjectIsTheServiceItself(t *testing.T) {
	checked := 0
	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			subject := finding.Subject()
			if subject.IsZero() {
				t.Errorf("%s: %s carries no subject", name, finding.Code())
				continue
			}
			if got := subject.Ref(); got != fixtureSubject {
				t.Errorf("%s: %s is about %q, want %q", name, finding.Code(), got,
					fixtureSubject)
			}
			if got := subject.Kind(); got != domain.SubjectKindTarget {
				t.Errorf("%s: %s carries subject kind %s, want %s",
					name, finding.Code(), got, domain.SubjectKindTarget)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no finding was checked; this guard would pass vacuously")
	}
}

// TestEveryAuthorizedKubernetesShapeBuildsAValidFinding.
//
// Both rules fold `domain.NewFinding`'s error, on the argument that every input
// they supply is a constant, a validated domain value taken from a node the
// graph already accepted, or an operation name from a closed map. That argument
// is only worth having if it is driven: this counts what the matrix produces and
// fails if any admitted shape silently produced nothing.
func TestEveryAuthorizedKubernetesShapeBuildsAValidFinding(t *testing.T) {
	// The scenarios that must produce something, and how many.
	expected := map[string]int{
		"service not found":                           1,
		"service read denied":                         1,
		"pod read denied, publication healthy":        1,
		"slice read denied, pods healthy":             1,
		"both list reads denied":                      2,
		"pod read denied, no ready endpoint":          2,
		"slice read denied, selector matched nothing": 2,
		"selector matched no pod":                     1,
		"no endpoint slice published":                 1,
		"slices published, none ready":                1,
		"slices published, all terminating":           1,
		"slices published, some terminating":          1,
		"no pod and no slice":                         1,
		"headless service selecting nothing":          1,
		"node port service with nothing ready":        1,
		"load balancer service selecting nothing":     1,
	}

	scenarios := everyScenario()
	for name, want := range expected {
		spec, exists := scenarios[name]
		if !exists {
			t.Fatalf("scenario %q no longer exists", name)
		}
		if got := len(spec.evaluate(t)); got != want {
			t.Errorf("%s produced %d findings, want %d; an admitted shape that builds "+
				"nothing is a conclusion silently dropped", name, got, want)
		}
	}
}

// stepsOf resolves a finding's references back to the steps they name.
func stepsOf(t *testing.T, graph domain.Graph, finding domain.Finding) []domain.Step {
	t.Helper()

	var out []domain.Step
	for _, ref := range finding.EvidenceRefs() {
		node, ok := graph.Node(ref)
		if !ok {
			t.Fatalf("%s cites %s, which is not in the graph", finding.Code(), ref)
		}
		out = append(out, node.Step())
	}
	return out
}

func sameSteps(got, want []domain.Step) bool {
	if len(got) != len(want) {
		return false
	}
	counts := map[domain.Step]int{}
	for _, step := range got {
		counts[step]++
	}
	for _, step := range want {
		counts[step]--
	}
	for _, remaining := range counts {
		if remaining != 0 {
			return false
		}
	}
	return true
}

// TestEveryRecommendationTextIsTheFrozenOne.
//
// # Why the structural checks were not enough
//
// The contract test above pins each recommendation's kind, safety class and
// self-collectability, and every one of those can be right while the sentence is
// wrong. *"Change this Service's selector to match the intended workload"* is a
// perfectly well-formed `NEXT_EVIDENCE`/`COMPARE` recommendation with
// `SelfCollectable: false` — and it is a remediation in every sense that matters
// to the operator reading it, telling them to edit a cluster svcdoctor has no
// expectation for.
//
// A mutation planting exactly that survived the whole suite, so the text is
// pinned byte for byte and the imperatives are refused by name.
func TestEveryRecommendationTextIsTheFrozenOne(t *testing.T) {
	frozen := map[domain.FindingCode]string{
		f1: "Verify the namespace and Service name this run declared against the " +
			"cluster it was pointed at",
		f2: "Verify whether the identity this run used is authorized to perform this " +
			"read in this namespace",
		f3: "Compare this Service's selector with the labels on the Pods intended to " +
			"back it",
		f4: "Compare the readiness the backing Pods report with the endpoints published " +
			"for this Service",
	}

	seen := map[domain.FindingCode]bool{}
	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			seen[finding.Code()] = true
			want, pinned := frozen[finding.Code()]
			if !pinned {
				t.Fatalf("%s: %s has no frozen recommendation", name, finding.Code())
			}
			for _, recommendation := range finding.Recommendations() {
				if got := recommendation.Action(); got != want {
					t.Errorf("%s: %s recommends\n  %q\nwant\n  %q",
						name, finding.Code(), got, want)
				}
			}
		}
	}
	for code := range frozen {
		if !seen[code] {
			t.Errorf("%s was never produced; its frozen recommendation is vacuous", code)
		}
	}
}

// TestNoRecommendationTellsAnOperatorToChangeAnything.
//
// The complement of the pin, stated as a rule rather than as a table, so that a
// **new** recommendation is refused on the day it is written rather than on the
// day somebody remembers to add a row above.
//
// Every entry is an imperative that would make svcdoctor an instruction rather
// than an observation. ADR 0094 section 2.7 forbids each of them permanently:
// change the selector · restart Pods · delete or recreate the Service · increase
// replicas · edit RBAC · grant cluster-admin · modify a NetworkPolicy.
func TestNoRecommendationTellsAnOperatorToChangeAnything(t *testing.T) {
	imperatives := []string{
		"change ", "create ", "delete ", "recreate ", "restart ", "scale ",
		"grant ", "edit ", "increase ", "decrease ", "add a ", "remove ",
		"apply ", "patch ", "set the ", "disable ", "enable ", "bind ",
	}

	checked := 0
	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			for _, recommendation := range finding.Recommendations() {
				checked++
				lowered := strings.ToLower(recommendation.Action())
				for _, imperative := range imperatives {
					if strings.HasPrefix(lowered, imperative) ||
						strings.Contains(lowered, " "+imperative) {
						t.Errorf("%s: %s recommends %q, which opens with the imperative "+
							"%q.\n\n"+
							"Every Kubernetes recommendation is a next observation. "+
							"svcdoctor has no expectation to compare a cluster against, "+
							"so it is not entitled to say what should be different "+
							"(ADR 0094 section 2.7).",
							name, finding.Code(), recommendation.Action(), imperative)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no recommendation was checked; this guard would pass vacuously")
	}
}
