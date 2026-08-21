package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustCode(t *testing.T, s string) FindingCode {
	t.Helper()
	c, err := NewFindingCode(s)
	if err != nil {
		t.Fatalf("NewFindingCode(%q): %v", s, err)
	}
	return c
}

func mustRecommendation(t *testing.T, action string) Recommendation {
	t.Helper()
	r, err := NewRecommendation(action)
	if err != nil {
		t.Fatalf("NewRecommendation(%q): %v", action, err)
	}
	return r
}

// validFindingInput returns an input that passes every check, so each test can
// change exactly the one field it is about.
func validFindingInput(t *testing.T) FindingInput {
	t.Helper()
	return FindingInput{
		Code:             mustCode(t, "DNS_RESOLUTION_FAILED"),
		Kind:             FindingKindConfirmed,
		Severity:         SeverityError,
		Confidence:       ConfidenceHigh,
		Layer:            LayerDNS,
		Summary:          "broker-2.internal did not resolve from this vantage point",
		EvidenceRefs:     []EvidenceID{mustID(t, "target/ep:broker-2.internal:9092/dns")},
		VantageDependent: true,
	}
}

func TestNewFindingConfirmed(t *testing.T) {
	in := validFindingInput(t)
	in.Subject = mustEndpointSubject(t, "broker-2.internal:9092")
	in.Detail = "The bootstrap endpoint answered, then advertised an address\nthis client cannot resolve."
	in.Recommendations = []Recommendation{
		mustRecommendation(t, "Verify that advertised.listeners resolves from this network."),
	}

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	if f.Code() != in.Code {
		t.Errorf("Code() = %q", f.Code())
	}
	if f.Kind() != FindingKindConfirmed {
		t.Errorf("Kind() = %s", f.Kind())
	}
	if f.Severity() != SeverityError {
		t.Errorf("Severity() = %s", f.Severity())
	}
	if f.Confidence() != ConfidenceHigh {
		t.Errorf("Confidence() = %s", f.Confidence())
	}
	if f.Layer() != LayerDNS {
		t.Errorf("Layer() = %s", f.Layer())
	}
	if f.Subject() != in.Subject {
		t.Errorf("Subject() = %s", f.Subject())
	}
	if f.Summary() != in.Summary {
		t.Errorf("Summary() = %q", f.Summary())
	}
	if f.Detail() != in.Detail {
		t.Errorf("Detail() = %q", f.Detail())
	}
	if !f.VantageDependent() {
		t.Error("VantageDependent() = false, want true")
	}
	if f.Discriminator() != "" {
		t.Errorf("Discriminator() = %q, want empty for CONFIRMED", f.Discriminator())
	}
	if f.EvidenceRefCount() != 1 {
		t.Errorf("EvidenceRefCount() = %d, want 1", f.EvidenceRefCount())
	}
	if len(f.Recommendations()) != 1 {
		t.Errorf("Recommendations() has %d entries, want 1", len(f.Recommendations()))
	}
	if f.IsZero() {
		t.Error("a constructed Finding must not be zero")
	}
}

func TestNewFindingHypothesis(t *testing.T) {
	in := validFindingInput(t)
	in.Kind = FindingKindHypothesis
	in.Confidence = ConfidenceMedium
	in.Discriminator = "Resolve broker-2.internal from inside the cluster network."

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	if f.Kind() != FindingKindHypothesis {
		t.Errorf("Kind() = %s", f.Kind())
	}
	if f.Discriminator() != in.Discriminator {
		t.Errorf("Discriminator() = %q", f.Discriminator())
	}
}

// TestHypothesisWithoutDiscriminatorIsAccepted pins the careful reading of the
// docs: REPORT_SCHEMA says the model "allows" a discriminator and FINDINGS says
// to "prefer" stating it. Neither requires it, and inventing a hard requirement
// here would be diagnosis policy rather than structural validation.
func TestHypothesisWithoutDiscriminatorIsAccepted(t *testing.T) {
	in := validFindingInput(t)
	in.Kind = FindingKindHypothesis
	in.Confidence = ConfidenceLow

	if _, err := NewFinding(in); err != nil {
		t.Fatalf("a hypothesis without a discriminator should be accepted: %v", err)
	}
}

// TestConfirmedWithDiscriminatorIsRejected is the one self-contradictory
// combination: a discriminator states what would settle an open question, and a
// confirmed finding has none to settle.
func TestConfirmedWithDiscriminatorIsRejected(t *testing.T) {
	in := validFindingInput(t)
	in.Kind = FindingKindConfirmed
	in.Discriminator = "Try again from another network."

	if _, err := NewFinding(in); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err = %v, want ErrInvalidValue", err)
	}
}

func TestNewFindingRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*FindingInput)
	}{
		{"empty code", func(in *FindingInput) { in.Code = "" }},
		{"malformed code", func(in *FindingInput) { in.Code = FindingCode("dns_failed") }},
		{"unspecified kind", func(in *FindingInput) { in.Kind = FindingKindUnspecified }},
		{"out of range kind", func(in *FindingInput) { in.Kind = FindingKind(99) }},
		{"unspecified severity", func(in *FindingInput) { in.Severity = SeverityUnspecified }},
		{"out of range severity", func(in *FindingInput) { in.Severity = Severity(99) }},
		{"unspecified confidence", func(in *FindingInput) { in.Confidence = ConfidenceUnspecified }},
		{"out of range confidence", func(in *FindingInput) { in.Confidence = Confidence(99) }},
		{"unspecified layer", func(in *FindingInput) { in.Layer = LayerUnspecified }},
		{"out of range layer", func(in *FindingInput) { in.Layer = Layer(99) }},
		{"empty summary", func(in *FindingInput) { in.Summary = "" }},
		{"summary with newline", func(in *FindingInput) { in.Summary = "line one\nline two" }},
		{"summary with trailing space", func(in *FindingInput) { in.Summary = "trailing " }},
		{"blank detail", func(in *FindingInput) { in.Detail = "   " }},
		{"detail with control char", func(in *FindingInput) { in.Detail = "bad\x00detail" }},
		{"no evidence refs", func(in *FindingInput) { in.EvidenceRefs = nil }},
		{"empty evidence refs", func(in *FindingInput) { in.EvidenceRefs = []EvidenceID{} }},
		{"invalid evidence ref", func(in *FindingInput) { in.EvidenceRefs = []EvidenceID{"bad ref\n"} }},
		{"zero recommendation", func(in *FindingInput) { in.Recommendations = []Recommendation{{}} }},
		{"discriminator with newline", func(in *FindingInput) {
			in.Kind = FindingKindHypothesis
			in.Discriminator = "one\ntwo"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validFindingInput(t)
			tt.mutate(&in)

			f, err := NewFinding(in)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if !f.IsZero() {
				t.Error("a rejected input must return the zero Finding")
			}
		})
	}
}

// TestSubjectIsOptional covers findings about the run as a whole rather than one
// endpoint. docs/FINDINGS.md section 3 does not list subject as required.
func TestSubjectIsOptional(t *testing.T) {
	in := validFindingInput(t)
	in.Subject = Subject{}

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("a finding without a subject should be accepted: %v", err)
	}
	if !f.Subject().IsZero() {
		t.Error("Subject() should stay zero")
	}

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(raw), `"subject"`) {
		t.Errorf("an absent subject should be omitted: %s", raw)
	}
}

func TestVantageDependentBothWays(t *testing.T) {
	for _, dependent := range []bool{true, false} {
		in := validFindingInput(t)
		in.VantageDependent = dependent

		f, err := NewFinding(in)
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		if f.VantageDependent() != dependent {
			t.Errorf("VantageDependent() = %v, want %v", f.VantageDependent(), dependent)
		}

		// Always present in the encoding: false is a statement, not an absence.
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if !strings.Contains(string(raw), `"vantageDependent"`) {
			t.Errorf("vantageDependent must always be encoded: %s", raw)
		}
	}
}

// TestEvidenceRefsAreDeduplicatedAndSorted covers the canonical normalization: a
// rule may assemble references from two sources that name the same node, and the
// encoded order must not depend on collection order.
func TestEvidenceRefsAreDeduplicatedAndSorted(t *testing.T) {
	in := validFindingInput(t)
	in.EvidenceRefs = []EvidenceID{
		mustID(t, "target/ep:z.internal:9092/dns"),
		mustID(t, "target/ep:a.internal:9092/dns"),
		mustID(t, "target/ep:z.internal:9092/dns"),
		mustID(t, "target/ep:m.internal:9092/dns"),
		mustID(t, "target/ep:a.internal:9092/dns"),
	}

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	want := []EvidenceID{
		"target/ep:a.internal:9092/dns",
		"target/ep:m.internal:9092/dns",
		"target/ep:z.internal:9092/dns",
	}
	if got := f.EvidenceRefs(); !equalIDs(got, want) {
		t.Errorf("EvidenceRefs() = %v, want %v", got, want)
	}
	if f.EvidenceRefCount() != 3 {
		t.Errorf("EvidenceRefCount() = %d, want 3", f.EvidenceRefCount())
	}
}

func TestEvidenceRefOrderIsIndependentOfInput(t *testing.T) {
	refs := []EvidenceID{
		mustID(t, "target/ep:a.internal:9092/dns"),
		mustID(t, "target/ep:m.internal:9092/tcp"),
		mustID(t, "target/ep:z.internal:9092/tls"),
	}
	orders := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}, {2, 0, 1}}

	var first []EvidenceID
	for _, order := range orders {
		in := validFindingInput(t)
		in.EvidenceRefs = nil
		for _, i := range order {
			in.EvidenceRefs = append(in.EvidenceRefs, refs[i])
		}

		f, err := NewFinding(in)
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		got := f.EvidenceRefs()
		if first == nil {
			first = got
			continue
		}
		if !equalIDs(got, first) {
			t.Errorf("order %v produced %v, want %v", order, got, first)
		}
	}
}

// TestInputMutationIsolation proves the caller cannot alter a recorded finding
// by reusing the slices it passed in.
func TestInputMutationIsolation(t *testing.T) {
	refs := []EvidenceID{mustID(t, "target/ep:a.internal:9092/dns")}
	recs := []Recommendation{mustRecommendation(t, "original action")}

	in := validFindingInput(t)
	in.EvidenceRefs = refs
	in.Recommendations = recs

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	refs[0] = "mutated"
	recs[0] = mustRecommendation(t, "mutated action")

	if got := f.EvidenceRefs(); got[0] != "target/ep:a.internal:9092/dns" {
		t.Errorf("evidence ref changed with the caller's slice: %q", got[0])
	}
	if got := f.Recommendations(); got[0].Action() != "original action" {
		t.Errorf("recommendation changed with the caller's slice: %q", got[0].Action())
	}
}

// TestOutputMutationIsolation proves a reader cannot alter a recorded finding
// through a returned slice.
func TestOutputMutationIsolation(t *testing.T) {
	in := validFindingInput(t)
	in.Recommendations = []Recommendation{mustRecommendation(t, "original action")}

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	refs := f.EvidenceRefs()
	refs[0] = "mutated"
	if got := f.EvidenceRefs(); got[0] == "mutated" {
		t.Error("evidence refs changed through a returned slice")
	}

	recs := f.Recommendations()
	recs[0] = mustRecommendation(t, "mutated action")
	if got := f.Recommendations(); got[0].Action() != "original action" {
		t.Errorf("recommendations changed through a returned slice: %q", got[0].Action())
	}
}

func TestFindingJSONConfirmed(t *testing.T) {
	in := validFindingInput(t)
	in.Subject = mustEndpointSubject(t, "broker-2.internal:9092")
	in.Recommendations = []Recommendation{mustRecommendation(t, "Check advertised.listeners.")}

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	got, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	const want = `{` +
		`"code":"DNS_RESOLUTION_FAILED",` +
		`"kind":"CONFIRMED",` +
		`"severity":"ERROR",` +
		`"confidence":"HIGH",` +
		`"layer":"L1",` +
		`"subject":{"kind":"ENDPOINT","ref":"broker-2.internal:9092"},` +
		`"summary":"broker-2.internal did not resolve from this vantage point",` +
		`"evidenceRefs":["target/ep:broker-2.internal:9092/dns"],` +
		`"recommendations":[{"action":"Check advertised.listeners."}],` +
		`"vantageDependent":true` +
		`}`
	if string(got) != want {
		t.Errorf("json.Marshal =\n%s\nwant\n%s", got, want)
	}
}

func TestFindingJSONHypothesis(t *testing.T) {
	in := validFindingInput(t)
	in.Code = mustCode(t, "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE")
	in.Kind = FindingKindHypothesis
	in.Confidence = ConfidenceMedium
	in.Layer = LayerTopology
	in.Summary = "an advertised broker may be unreachable from this vantage point"
	in.Discriminator = "Retry the same check from inside the cluster network."

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	got, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	const want = `{` +
		`"code":"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",` +
		`"kind":"HYPOTHESIS",` +
		`"severity":"ERROR",` +
		`"confidence":"MEDIUM",` +
		`"layer":"L6",` +
		`"summary":"an advertised broker may be unreachable from this vantage point",` +
		`"evidenceRefs":["target/ep:broker-2.internal:9092/dns"],` +
		`"vantageDependent":true,` +
		`"discriminator":"Retry the same check from inside the cluster network."` +
		`}`
	if string(got) != want {
		t.Errorf("json.Marshal =\n%s\nwant\n%s", got, want)
	}
}

func TestFindingJSONIsDeterministic(t *testing.T) {
	in := validFindingInput(t)
	in.EvidenceRefs = []EvidenceID{
		mustID(t, "target/ep:z.internal:9092/dns"),
		mustID(t, "target/ep:a.internal:9092/dns"),
		mustID(t, "target/ep:m.internal:9092/dns"),
	}
	in.Recommendations = []Recommendation{
		mustRecommendation(t, "first action"),
		mustRecommendation(t, "second action"),
	}

	f, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	first, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(first) != string(again) {
			t.Fatalf("encoding varied between runs:\n%s\n%s", first, again)
		}
	}
}

// TestFindingJSONUsesSymbolicEnums guards against enum ordinals reaching the
// report contract.
func TestFindingJSONUsesSymbolicEnums(t *testing.T) {
	f, err := NewFinding(validFindingInput(t))
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded struct {
		Kind       string `json:"kind"`
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		Layer      string `json:"layer"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Kind != "CONFIRMED" || decoded.Severity != "ERROR" ||
		decoded.Confidence != "HIGH" || decoded.Layer != "L1" {
		t.Errorf("expected symbolic enum values, got %+v", decoded)
	}
}

func TestFindingJSONOmitsEmptyOptionalFields(t *testing.T) {
	f, err := NewFinding(validFindingInput(t))
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, absent := range []string{"subject", "detail", "recommendations", "discriminator"} {
		if _, present := decoded[absent]; present {
			t.Errorf("%q should be omitted when it carries no information", absent)
		}
	}
	for _, required := range []string{"code", "kind", "severity", "confidence", "layer", "summary", "evidenceRefs", "vantageDependent"} {
		if _, present := decoded[required]; !present {
			t.Errorf("%q must always be present", required)
		}
	}
}

func TestZeroFindingIsInvalid(t *testing.T) {
	var f Finding

	if !f.IsZero() {
		t.Error("the zero Finding should report IsZero")
	}
	if f.String() != "<invalid finding>" {
		t.Errorf("String() = %q", f.String())
	}
	if f.EvidenceRefs() != nil || f.Recommendations() != nil {
		t.Error("the zero Finding should return nothing")
	}
	if _, err := json.Marshal(f); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal err = %v, want ErrInvalidValue", err)
	}
}

func TestFindingString(t *testing.T) {
	f, err := NewFinding(validFindingInput(t))
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	const want = "DNS_RESOLUTION_FAILED L1 ERROR/HIGH CONFIRMED: " +
		"broker-2.internal did not resolve from this vantage point"
	if got := f.String(); got != want {
		t.Errorf("String() = %q,\nwant %q", got, want)
	}
}

// TestFindingHasNoGraphOrEvidenceDependency is the ADR 0014 boundary expressed
// as a property of the type: a finding points at evidence by identifier, never
// by holding a graph or copying evidence values into itself.
func TestFindingHasNoGraphOrEvidenceDependency(t *testing.T) {
	var f any = Finding{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"Graph", hasMethod[interface{ Graph() Graph }](f)},
		{"Evidence", hasMethod[interface{ Evidence() []Evidence }](f)},
		{"Resolve", hasMethod[interface{ Resolve(Graph) []Evidence }](f)},
		{"Validate with graph", hasMethod[interface{ Validate(Graph) error }](f)},
		{"Err", hasMethod[interface{ Err() error }](f)},
		{"Raw", hasMethod[interface{ Raw() any }](f)},
		{"Metadata", hasMethod[interface{ Metadata() map[string]any }](f)},
	}

	for _, x := range forbidden {
		if x.has {
			t.Errorf("Finding must not expose %s", x.name)
		}
	}

	// The constructor takes no graph either.
	in := validFindingInput(t)
	in.EvidenceRefs = []EvidenceID{mustID(t, "node/that/exists/in/no/graph")}
	if _, err := NewFinding(in); err != nil {
		t.Fatalf("a finding must be constructible without any graph: %v", err)
	}
}
