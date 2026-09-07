package kubernetes_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// The claim ceilings, as tests.
//
// # Why a per-code list rather than one global banned-word set
//
// Because context decides. "unreachable" is a correct and necessary word in the
// generic transport findings, which measure reachability; it is a forbidden word
// here, because svcdoctor connected to nothing. A global list would either break
// four other services or be watered down until it caught nothing.
//
// Each entry names a claim ADR 0094 section 2.7 forbids **permanently**, and the
// reason it names is the reason it is forbidden — so a future author who trips
// one reads why rather than deleting the row.

// forbiddenPhrase is one thing a code's prose may never contain.
type forbiddenPhrase struct {
	phrase string
	why    string
}

func claimCeilings() map[domain.FindingCode][]forbiddenPhrase {
	// The claims no Kubernetes finding may make at all, whichever code it is.
	universal := []forbiddenPhrase{
		{"misconfigur", "svcdoctor has no expectation to compare a cluster against, so it " +
			"cannot know that anything was configured wrongly (ADR 0083 section 2.6)"},
		{"root cause", "these findings restate what an authoritative source stated; none " +
			"of them attributes a cause"},
		{"caused by", "an observation is not a cause"},
		{"unhealthy", "svcdoctor read three objects and connected to nothing"},
		{"is broken", "no finding here observes any component's condition"},
		{"is down", "no finding here observes any component's condition"},
		{"kube-proxy", "svcdoctor never observed a proxy"},
		{"networkpolicy", "svcdoctor never observed a NetworkPolicy"},
		{"network policy", "svcdoctor never observed a NetworkPolicy"},
		{"cluster-admin", "svcdoctor never recommends widening a permission, and least of " +
			"all to the widest one there is"},
		{"cilium", "svcdoctor observed no CNI"},
		{"service mesh", "svcdoctor observed no mesh"},
		{"crashloop", "no Pod field is in the graph at all"},
		{"oomkilled", "no Pod field is in the graph at all"},
		{"imagepull", "no Pod field is in the graph at all"},
	}

	return map[domain.FindingCode][]forbiddenPhrase{
		f1: append([]forbiddenPhrase{
			{"was deleted", "a NotFound is not a history; svcdoctor did not observe the " +
				"Service existing and then stopping"},
			{"never existed", "the same, in the other direction"},
			{"namespace is wrong", "svcdoctor does not know what the operator meant"},
			{"name is wrong", "svcdoctor does not know what the operator meant"},
			{"context is wrong", "svcdoctor does not know what the operator meant"},
			{"create the service", "absence may be exactly what somebody intended"},
			{"does not exist", "a NotFound can also be returned in some authorization " +
				"configurations, so the claim stops at what the API reported"},
		}, universal...),

		f2: append([]forbiddenPhrase{
			{"rbac", "a 403 says the read was refused; it says nothing about why the " +
				"policy was authored that way"},
			{"serviceaccount", "the same"},
			{"role binding", "the same"},
			{"rolebinding", "the same"},
			{"clusterrole", "the same"},
			{"grant", "svcdoctor never recommends widening a permission"},
			{"no pods", "a denied read is never emptiness; the set it would have produced " +
				"is unavailable, which is a different fact"},
			{"no endpoints", "the same"},
			{"are absent", "the same"},
		}, universal...),

		f3: append([]forbiddenPhrase{
			{"selector is wrong", "many configurations produce this observation and " +
				"svcdoctor measured one of them"},
			{"wrong selector", "the same"},
			{"deployment is missing", "svcdoctor read no Deployment"},
			{"pods crashed", "no Pod field is in the graph at all"},
			{"scaled down", "svcdoctor read no replica count, and a workload deliberately " +
				"held at zero produces this observation truthfully"},
			{"no backend", "that is a conclusion about traffic, and svcdoctor sent none"},
			{"unavailable", "publication and availability are different claims"},
			{"unreachable", "svcdoctor connected to nothing"},
			{"application is down", "svcdoctor observed no application"},
		}, universal...),

		f4: append([]forbiddenPhrase{
			{"unreachable", "topology-aware routing, traffic policies, mesh interception " +
				"and the all-terminating case each break the equation between publication " +
				"and reachability (ADR 0093 section 2.5)"},
			{"cannot connect", "svcdoctor connected to nothing"},
			{"no traffic", "a proxy may still route to terminating endpoints"},
			{"unavailable", "publication is not availability"},
			{"readiness probe", "svcdoctor read no probe and no Pod condition"},
			{"not ready", "the published fact is that no endpoint reports itself ready; " +
				"saying a backend is 'not ready' attributes the state to the backend"},
			{"controller is broken", "svcdoctor observed no controller"},
			{"endpointslice controller", "the same"},
			{"selector is wrong", "this finding is not about the selector at all"},
			{"pods are", "no Pod field is in the graph at all"},
			// Any word implying persistence. The whole claim is scoped to the
			// instant of the observation.
			//
			// These are the phrases that assert the *state continues*, not every
			// word that could. A bare "still" was tried and rejected: the
			// all-terminating note legitimately says a proxy "may still route to
			// them", which is a statement about routing rather than about how
			// long this observation holds — and banning it would have meant
			// deleting the one sentence that stops "no ready endpoint" being
			// read as "no traffic".
			{"permanently", "the claim is scoped to the time of these observations"},
			{"will remain", "the claim is scoped to the time of these observations"},
			{"continues to", "the claim is scoped to the time of these observations"},
			{"is still", "the claim is scoped to the time of these observations"},
			{"has been", "svcdoctor observed one moment and holds no history"},
			{"ongoing", "the claim is scoped to the time of these observations"},
		}, universal...),
	}
}

// TestNoKubernetesFindingEverExceedsItsClaimCeiling.
func TestNoKubernetesFindingEverExceedsItsClaimCeiling(t *testing.T) {
	ceilings := claimCeilings()
	checked := map[domain.FindingCode]int{}

	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			checked[finding.Code()]++
			prose := strings.ToLower(proseOf(finding))
			for _, forbidden := range ceilings[finding.Code()] {
				if strings.Contains(prose, strings.ToLower(forbidden.phrase)) {
					t.Errorf("%s: %s says %q.\n\n%s\n\n--- prose ---\n%s",
						name, finding.Code(), forbidden.phrase, forbidden.why,
						proseOf(finding))
				}
			}
		}
	}

	for _, code := range []domain.FindingCode{f1, f2, f3, f4} {
		if checked[code] == 0 {
			t.Errorf("%s was never produced; its ceiling is vacuous", code)
		}
	}
}

// TestTheForbiddenPhrasePredicateActuallyMatches is the non-vacuity check.
//
// A scan whose predicate is broken passes everything. This plants each forbidden
// phrase into a string and requires the same comparison to find it, so the guard
// above cannot be silently disarmed by a change to how prose is assembled.
func TestTheForbiddenPhrasePredicateActuallyMatches(t *testing.T) {
	total := 0
	for code, phrases := range claimCeilings() {
		for _, forbidden := range phrases {
			total++
			planted := strings.ToLower("The finding says " + forbidden.phrase + " about it.")
			if !strings.Contains(planted, strings.ToLower(forbidden.phrase)) {
				t.Errorf("%s: the predicate does not match a planted %q",
					code, forbidden.phrase)
			}
		}
	}
	if total == 0 {
		t.Fatal("no forbidden phrase is declared at all")
	}
}

// TestTheClaimProseSaysWhatTheEvidenceCarries is the positive half.
//
// A ceiling test alone would pass on empty prose. These are the sentences each
// finding must contain, and each is the part of the claim that keeps it bounded:
// the temporal scope, the completeness statement, and the explicit refusal to
// make the stronger claim.
func TestTheClaimProseSaysWhatTheEvidenceCarries(t *testing.T) {
	required := map[domain.FindingCode][]string{
		f1: {
			"the Kubernetes API reported",
			"at the time of that one observation",
		},
		f2: {
			"was not made",
			"is a different fact from empty",
		},
		f3: {
			"at the time of these API observations",
			"the enumeration was complete",
		},
		f4: {
			"at the time of these API observations",
			"the enumeration was complete",
			"publishes and not whether anything can be reached",
		},
	}

	seen := map[domain.FindingCode]bool{}
	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			seen[finding.Code()] = true
			prose := proseOf(finding)
			for _, phrase := range required[finding.Code()] {
				// Case-insensitive, because a sentence-initial capital is a
				// property of where the phrase lands rather than of the claim.
				if !strings.Contains(
					strings.ToLower(prose), strings.ToLower(phrase),
				) {
					t.Errorf("%s: %s does not say %q.\n\n--- prose ---\n%s",
						name, finding.Code(), phrase, prose)
				}
			}
		}
	}
	for code := range required {
		if !seen[code] {
			t.Errorf("%s was never produced; its required prose is vacuous", code)
		}
	}
}

// TestNoClusterSuppliedValueCanReachAnyFindingsProse.
//
// # Why this is driven with hostile values rather than argued
//
// The graph carries no label, no Pod name, no endpoint address and no
// `Status.Message` (ADR 0094 section 11.2), so the structural claim is that
// there is nothing to interpolate. This drives the one class of value that *is*
// on a node — the identity attributes and the counts — with hostile content and
// requires none of it to appear in prose.
//
// A namespace and a Service name are operator-chosen strings that reach the
// subject and the evidence, where redaction transforms them. Prose is where
// they must not be (docs/FINDINGS.md section 3.1 rule 15).
func TestNoClusterSuppliedValueCanReachAnyFindingsProse(t *testing.T) {
	hostile := []string{
		"\x1b[31mRED",
		"line\r\nInjected: header",
		"' OR 1=1 --",
		strings.Repeat("A", 300),
		"../../etc/passwd",
		"Bearer eyJhbGciOi",
	}

	produced := 0
	for _, value := range hostile {
		spec := healthy()
		spec.podSet = podSetNode(true, 0)
		spec.service = serviceNode(servicekubernetes.ServiceTypeClusterIP, true, 3)
		// Hostile values on the two identity attributes the Service node carries.
		spec.service.attributes[servicekubernetes.AttrNamespace] = domain.IdentityAttr(value)
		spec.service.attributes[servicekubernetes.AttrServiceName] = domain.IdentityAttr(value)
		// And on the auth mode, which is the only string the api_access node has.
		spec.apiAccess.attributes[servicekubernetes.AttrAuthMode] = domain.StringAttr(value)

		findings := spec.evaluate(t)
		if len(findings) == 0 {
			t.Fatalf("the hostile fixture produced no finding; the guard would be vacuous")
		}
		for _, finding := range findings {
			produced++
			prose := proseOf(finding)
			if strings.Contains(prose, value) {
				t.Errorf("%s interpolated a cluster-supplied value into its prose.\n\n"+
					"--- prose ---\n%s", finding.Code(), prose)
			}
			for _, control := range []string{"\x1b", "\r", "\n\n\n"} {
				if strings.Contains(prose, control) {
					t.Errorf("%s prose contains %q", finding.Code(), control)
				}
			}
		}
	}
	if produced == 0 {
		t.Fatal("nothing was checked; this guard would pass vacuously")
	}
}

// TestNoCountEverReachesAnyFindingsProse.
//
// The counts decide *which* constant is emitted; none of them is rendered into
// one. That keeps every sentence a fixed string a test can pin byte for byte,
// and it keeps a cluster's cardinality — how many Pods, how many slices, how
// many endpoints — out of a document that may be shared.
//
// It is driven by varying the counts and requiring the prose not to change.
func TestNoCountEverReachesAnyFindingsProse(t *testing.T) {
	base := healthy()
	base.publication = publicationNode(publicationCounts{slices: 1, endpoints: 1, ready: 0})
	want := proseOf(single(t, base.evaluate(t)))

	for _, counts := range []publicationCounts{
		{slices: 2, endpoints: 7, ready: 0},
		{slices: 256, endpoints: 9999, ready: 0},
		{slices: 1, endpoints: 1, ready: 0, excluded: 42},
		{slices: 3, endpoints: 5, ready: 0, external: true},
	} {
		spec := healthy()
		spec.publication = publicationNode(counts)
		if got := proseOf(single(t, spec.evaluate(t))); got != want {
			t.Errorf("changing the counts changed the prose.\n\nwith %+v:\n%s\n\n"+
				"want:\n%s", counts, got, want)
		}
	}
}

// proseOf is everything a finding says.
func proseOf(finding domain.Finding) string {
	parts := []string{finding.Summary(), finding.Detail(), finding.Discriminator()}
	for _, recommendation := range finding.Recommendations() {
		parts = append(parts, recommendation.Action(), recommendation.Rationale())
	}
	return strings.Join(parts, "\n")
}

func single(t testing.TB, findings []domain.Finding) domain.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %v", codesOf(findings))
	}
	return findings[0]
}
