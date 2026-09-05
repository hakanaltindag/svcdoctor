package diagnosis

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1B: the merge-compatibility contract.
//
// ADR 0081 section 2.1 makes semantic identity (Code, Subject). Phase 10.1B
// clarifies that identity is a *candidacy* test rather than a licence: two
// findings that share an identity may be merged only when every field a
// consumer parses already agrees, because a merged finding must not carry a
// value neither rule stated.
//
// The frozen matrix is in docs/decisions/0081-…md section 2.2a and in
// docs/validation/PHASE101B_DIAGNOSTIC_ACTIVATION_VALIDATION.md.

// mergeInput builds one finding with every canonical field controllable.
type mergeInput struct {
	rule             RuleID
	code             string
	subjectRef       string
	layer            domain.Layer
	kind             domain.FindingKind
	severity         domain.Severity
	confidence       domain.Confidence
	summary          string
	detail           string
	discriminator    string
	vantageDependent bool
	refs             []domain.EvidenceID
	actions          []string
}

func (m mergeInput) build(t *testing.T) AttributedFinding {
	t.Helper()

	subject := endpointSubject(t, m.subjectRef)
	var recommendations []domain.Recommendation
	for _, action := range m.actions {
		recommendations = append(recommendations, recommendation(t, action))
	}

	f, err := domain.NewFinding(domain.FindingInput{
		Code:             domain.FindingCode(m.code),
		Kind:             m.kind,
		Severity:         m.severity,
		Confidence:       m.confidence,
		Layer:            m.layer,
		Subject:          subject,
		Summary:          m.summary,
		Detail:           m.detail,
		Discriminator:    m.discriminator,
		VantageDependent: m.vantageDependent,
		EvidenceRefs:     m.refs,
		Recommendations:  recommendations,
	})
	if err != nil {
		t.Fatalf("NewFinding(%s): %v", m.code, err)
	}
	return AttributedFinding{Rule: m.rule, Finding: f}
}

// notPermittedAt reproduces the production shape this whole contract exists for.
//
// POSTGRES_CONNECTION_NOT_PERMITTED is built by two rules about one endpoint at
// two layers, with prose deliberately shared so the claim cannot drift into two
// wordings. See internal/diagnosis/postgres/shared.go.
func notPermittedAt(rule RuleID, layer domain.Layer, ref domain.EvidenceID) mergeInput {
	return mergeInput{
		rule: rule, code: "POSTGRES_CONNECTION_NOT_PERMITTED",
		subjectRef: "pg.example:5432", layer: layer,
		kind: domain.FindingKindConfirmed, severity: domain.SeverityError,
		confidence: domain.ConfidenceHigh, vantageDependent: true,
		summary: "The PostgreSQL endpoint refused this connection before evaluating any credential",
		refs:    []domain.EvidenceID{ref},
	}
}

// TestMC01SameLayerConverges is the positive case: everything a consumer parses
// agrees, so two routes become one finding carrying both.
func TestMC01SameLayerConverges(t *testing.T) {
	got := mustConverge(t, []AttributedFinding{
		notPermittedAt("postgres/startup", domain.LayerProtocol, "startup-node").build(t),
		notPermittedAt("postgres/authentication", domain.LayerProtocol, "auth-node").build(t),
	})

	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Layer() != domain.LayerProtocol {
		t.Errorf("Layer = %s, want L4", got[0].Layer())
	}
	if want := []domain.EvidenceID{"auth-node", "startup-node"}; !slices.Equal(got[0].EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want the union %v", got[0].EvidenceRefs(), want)
	}
}

// TestMC02DifferentLayerMustNotConverge is the defect Phase 10.1B was stopped by.
//
// Before the clarification this merged into one finding claiming L5 while citing
// the startup node — a protocol-stage refusal published as an authentication
// stage claim, decided by "postgres/a…" sorting before "postgres/s…".
func TestMC02DifferentLayerMustNotConverge(t *testing.T) {
	got := mustConverge(t, []AttributedFinding{
		notPermittedAt("postgres/startup", domain.LayerProtocol, "startup-node").build(t),
		notPermittedAt("postgres/authentication", domain.LayerAuth, "auth-node").build(t),
	})

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2; a differing layer means the two rules did "+
			"not observe one thing", len(got))
	}

	byLayer := map[domain.Layer][]domain.EvidenceID{}
	for _, f := range got {
		byLayer[f.Layer()] = f.EvidenceRefs()
	}
	if refs, ok := byLayer[domain.LayerProtocol]; !ok ||
		!slices.Equal(refs, []domain.EvidenceID{"startup-node"}) {
		t.Errorf("the L4 finding cites %v, want [startup-node]", refs)
	}
	if refs, ok := byLayer[domain.LayerAuth]; !ok ||
		!slices.Equal(refs, []domain.EvidenceID{"auth-node"}) {
		t.Errorf("the L5 finding cites %v, want [auth-node]", refs)
	}

	// Neither finding may cite the other's evidence: that is what the pre-fix
	// behaviour did, and it is what made the published layer wrong.
	for _, f := range got {
		if len(f.EvidenceRefs()) != 1 {
			t.Errorf("the %s finding cites %v; evidence crossed the layer boundary",
				f.Layer(), f.EvidenceRefs())
		}
	}
}

// TestMC03NoFieldIsChosenByRuleOrder is the general form of the user-facing
// contract: swap the rule identities and nothing a consumer parses may move.
func TestMC03NoFieldIsChosenByRuleOrder(t *testing.T) {
	forward := []AttributedFinding{
		notPermittedAt("postgres/aaa-first", domain.LayerProtocol, "startup-node").build(t),
		notPermittedAt("postgres/zzz-last", domain.LayerAuth, "auth-node").build(t),
	}
	// The same two findings with their identities exchanged, so whichever rule
	// name sorts first now holds the *other* layer.
	swapped := []AttributedFinding{
		notPermittedAt("postgres/zzz-last", domain.LayerProtocol, "startup-node").build(t),
		notPermittedAt("postgres/aaa-first", domain.LayerAuth, "auth-node").build(t),
	}

	a, err := json.Marshal(mustConverge(t, forward))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	b, err := json.Marshal(mustConverge(t, swapped))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("exchanging rule identities changed the canonical output:\n%s\n%s", a, b)
	}
}

// TestMC04RegistrationOrderCannotReachAnyCanonicalField drives the whole engine
// rather than Converge alone, because registration order is an engine concept.
func TestMC04RegistrationOrderCannotReachAnyCanonicalField(t *testing.T) {
	g, subject := linearGraph(t)

	ruleAt := func(layer domain.Layer, ref domain.EvidenceID, severity domain.Severity,
		confidence domain.Confidence, vantage bool, summary string) Rule {
		return func(RuleContext) []domain.Finding {
			f, err := domain.NewFinding(domain.FindingInput{
				Code: "TCP_CONNECTION_REFUSED", Kind: domain.FindingKindConfirmed,
				Severity: severity, Confidence: confidence, Layer: layer, Subject: subject,
				Summary: summary, VantageDependent: vantage,
				EvidenceRefs: []domain.EvidenceID{ref},
			})
			if err != nil {
				t.Fatalf("NewFinding: %v", err)
			}
			return []domain.Finding{f}
		}
	}

	rules := []struct {
		id   string
		rule Rule
	}{
		{"a/one", ruleAt(domain.LayerTCP, "a-tcp", domain.SeverityWarn,
			domain.ConfidenceLow, false, "a claim from the first route")},
		{"b/two", ruleAt(domain.LayerTCP, "a-dns", domain.SeverityError,
			domain.ConfidenceHigh, true, "b claim from the second route")},
		{"c/three", ruleAt(domain.LayerDNS, "a-dns", domain.SeverityInfo,
			domain.ConfidenceMedium, false, "c claim at another layer entirely")},
	}

	var want string
	for i, order := range permutations(len(rules)) {
		set := NewRuleSet()
		for _, index := range order {
			set.Add(rules[index].id, rules[index].rule)
		}
		registry, err := set.Freeze()
		if err != nil {
			t.Fatalf("Freeze: %v", err)
		}

		encoded, err := json.Marshal(NewEngine(registry).Diagnose(RuleContext{Graph: g}))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if i == 0 {
			want = string(encoded)
			continue
		}
		if string(encoded) != want {
			t.Fatalf("registration order %v changed the canonical report:\nwant %s\ngot  %s",
				order, want, encoded)
		}
	}

	// And the two compatible routes really did merge, so this is not passing
	// because nothing converged.
	set := NewRuleSet()
	for _, r := range rules {
		set.Add(r.id, r.rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	got := NewEngine(registry).Diagnose(RuleContext{Graph: g})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 — the two L2 routes merged, the L1 one did not",
			len(got))
	}
	for _, f := range got {
		if f.Layer() != domain.LayerTCP {
			continue
		}
		if got, want := f.Severity(), domain.SeverityError; got != want {
			t.Errorf("Severity = %s, want the maximum %s", got, want)
		}
		if got, want := f.Confidence(), domain.ConfidenceHigh; got != want {
			t.Errorf("Confidence = %s, want the maximum %s", got, want)
		}
		if !f.VantageDependent() {
			t.Error("VantageDependent = false, want the logical OR")
		}
		if want := []domain.EvidenceID{"a-dns", "a-tcp"}; !slices.Equal(f.EvidenceRefs(), want) {
			t.Errorf("EvidenceRefs = %v, want the union %v", f.EvidenceRefs(), want)
		}
	}
}

// TestMC05DifferingDiscriminatorsMustNotConverge covers the second MUST_EQUAL
// field.
//
// Two hypotheses asking different questions are not one hypothesis. The
// discriminator is measured constant across every construction site in the tree
// today, so this fires nowhere and exists to keep it that way.
func TestMC05DifferingDiscriminatorsMustNotConverge(t *testing.T) {
	base := mergeInput{
		code: "TCP_CONNECTION_REFUSED", subjectRef: "a.example:9092",
		layer: domain.LayerTCP, kind: domain.FindingKindHypothesis,
		severity: domain.SeverityWarn, confidence: domain.ConfidenceLow,
		summary: "the endpoint did not accept a connection",
	}

	first := base
	first.rule, first.refs = "a/one", []domain.EvidenceID{"n1"}
	first.discriminator = "whether the address is routable from this network"

	second := base
	second.rule, second.refs = "b/two", []domain.EvidenceID{"n2"}
	second.discriminator = "whether any process is listening on that port"

	got := mustConverge(t, []AttributedFinding{first.build(t), second.build(t)})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2; two open questions are not one", len(got))
	}
}

// TestMC06AnUnsetDiscriminatorJoinsTheOnlyQuestionAsked pins the asymmetry.
//
// Silence is not a second, conflicting question. It is also not a reason to drop
// the only question anybody asked — which is what taking the winner's value
// would do whenever the silent rule sorts first.
func TestMC06AnUnsetDiscriminatorJoinsTheOnlyQuestionAsked(t *testing.T) {
	const question = "whether the address is routable from this network"

	base := mergeInput{
		code: "TCP_CONNECTION_REFUSED", subjectRef: "a.example:9092",
		layer: domain.LayerTCP, kind: domain.FindingKindHypothesis,
		severity: domain.SeverityWarn, confidence: domain.ConfidenceLow,
		summary: "the endpoint did not accept a connection",
	}

	// "a/silent" sorts first and asks nothing; the merged finding must still
	// carry the question "b/asks" raised.
	silent := base
	silent.rule, silent.refs = "a/silent", []domain.EvidenceID{"n1"}

	asks := base
	asks.rule, asks.refs = "b/asks", []domain.EvidenceID{"n2"}
	asks.discriminator = question

	got := mustConverge(t, []AttributedFinding{silent.build(t), asks.build(t)})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Discriminator() != question {
		t.Errorf("Discriminator = %q, want %q — the winner's silence dropped the "+
			"only open question", got[0].Discriminator(), question)
	}
}

// TestMC07AConfirmedMergeClearsTheDiscriminator pins ADR 0081 section 2.2's last
// clause, and that it survives the new partitioning.
func TestMC07AConfirmedMergeClearsTheDiscriminator(t *testing.T) {
	base := mergeInput{
		code: "TCP_CONNECTION_REFUSED", subjectRef: "a.example:9092",
		layer: domain.LayerTCP, severity: domain.SeverityError,
		confidence: domain.ConfidenceHigh,
		summary:    "the endpoint did not accept a connection",
	}

	guess := base
	guess.rule, guess.refs = "a/guess", []domain.EvidenceID{"n1"}
	guess.kind = domain.FindingKindHypothesis
	guess.discriminator = "whether the address is routable from this network"

	proof := base
	proof.rule, proof.refs = "b/proof", []domain.EvidenceID{"n2"}
	proof.kind = domain.FindingKindConfirmed

	got := mustConverge(t, []AttributedFinding{guess.build(t), proof.build(t)})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Kind() != domain.FindingKindConfirmed {
		t.Errorf("Kind = %s, want CONFIRMED to absorb HYPOTHESIS", got[0].Kind())
	}
	if got[0].Discriminator() != "" {
		t.Errorf("Discriminator = %q; a proven claim has no open question left",
			got[0].Discriminator())
	}
}

// TestMC08EvidenceIsNeverLost is the property that makes refusing to merge safe.
//
// Whether two findings converge or stay apart, every evidence identifier any
// rule cited must still be reachable from the output. Refusing to merge must not
// become a way to drop a route.
func TestMC08EvidenceIsNeverLost(t *testing.T) {
	cases := [][]AttributedFinding{
		{
			notPermittedAt("postgres/startup", domain.LayerProtocol, "startup-node").build(t),
			notPermittedAt("postgres/authentication", domain.LayerAuth, "auth-node").build(t),
		},
		{
			notPermittedAt("postgres/startup", domain.LayerProtocol, "startup-node").build(t),
			notPermittedAt("postgres/authentication", domain.LayerProtocol, "auth-node").build(t),
		},
	}

	for i, in := range cases {
		want := map[domain.EvidenceID]bool{}
		for _, af := range in {
			for _, ref := range af.Finding.EvidenceRefs() {
				want[ref] = true
			}
		}

		got := map[domain.EvidenceID]bool{}
		for _, f := range mustConverge(t, in) {
			for _, ref := range f.EvidenceRefs() {
				got[ref] = true
			}
		}

		for ref := range want {
			if !got[ref] {
				t.Errorf("case %d lost evidence %q", i, ref)
			}
		}
		for ref := range got {
			if !want[ref] {
				t.Errorf("case %d invented evidence %q", i, ref)
			}
		}
	}
}

// TestMC09ConfidenceDoesNotVoteUpwardAcrossCompatibilityGroups is the confidence
// half, checked where the new partitioning could have broken it.
func TestMC09ConfidenceDoesNotVoteUpwardAcrossCompatibilityGroups(t *testing.T) {
	base := mergeInput{
		code: "TCP_CONNECTION_REFUSED", subjectRef: "a.example:9092",
		layer: domain.LayerTCP, kind: domain.FindingKindHypothesis,
		severity: domain.SeverityWarn, confidence: domain.ConfidenceMedium,
		summary: "the endpoint did not accept a connection",
	}

	var in []AttributedFinding
	for _, rule := range []RuleID{"a/one", "b/two", "c/three", "d/four", "e/five"} {
		route := base
		route.rule = rule
		route.refs = []domain.EvidenceID{domain.EvidenceID("n-" + string(rule[0]))}
		in = append(in, route.build(t))

		got := mustConverge(t, in)
		if len(got) != 1 {
			t.Fatalf("%d routes produced %d findings, want 1", len(in), len(got))
		}
		if got[0].Confidence() != domain.ConfidenceMedium {
			t.Fatalf("%d MEDIUM routes produced %s; convergence is not a vote",
				len(in), got[0].Confidence())
		}
	}
}

// TestMC10PartitioningIsDeterministic drives every input permutation, because
// the partitioner walks a map.
func TestMC10PartitioningIsDeterministic(t *testing.T) {
	in := []AttributedFinding{
		notPermittedAt("postgres/startup", domain.LayerProtocol, "startup-node").build(t),
		notPermittedAt("postgres/authentication", domain.LayerAuth, "auth-node").build(t),
		notPermittedAt("postgres/session", domain.LayerAuth, "session-node").build(t),
		notPermittedAt("postgres/tls", domain.LayerTLS, "tls-node").build(t),
	}

	want, err := json.Marshal(mustConverge(t, in))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	for _, order := range permutations(len(in)) {
		shuffled := make([]AttributedFinding, 0, len(in))
		for _, index := range order {
			shuffled = append(shuffled, in[index])
		}
		got, err := json.Marshal(mustConverge(t, shuffled))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("permutation %v changed the result:\nwant %s\ngot  %s", order, want, got)
		}
	}

	// Three layers, and the two same-layer routes merged: three findings.
	if got := mustConverge(t, in); len(got) != 3 {
		t.Errorf("got %d findings, want 3 (L3, L4, and one merged L5)", len(got))
	}
}
