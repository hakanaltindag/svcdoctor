package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testStart = time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

// validInput returns an input that passes every check, so each test can change
// exactly the one field it is about.
func validInput(t *testing.T) EvidenceInput {
	t.Helper()
	return EvidenceInput{
		ID:        mustID(t, "target/ep:kafka.internal:9092/dns"),
		Subject:   mustEndpointSubject(t, "kafka.internal:9092"),
		Layer:     LayerDNS,
		Step:      mustStep(t, "dns.lookup"),
		State:     StatePass,
		StartedAt: testStart,
		Duration:  12 * time.Millisecond,
	}
}

func TestNewEvidenceAccessors(t *testing.T) {
	in := validInput(t)
	in.Attributes = map[AttributeKey]AttrValue{
		"dns.rcode":     StringAttr("NOERROR"),
		"dns.addresses": StringListAttr("10.0.1.7", "10.0.1.8"),
	}

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	if e.ID() != in.ID {
		t.Errorf("ID() = %q, want %q", e.ID(), in.ID)
	}
	if e.Subject() != in.Subject {
		t.Errorf("Subject() = %s, want %s", e.Subject(), in.Subject)
	}
	if e.Layer() != LayerDNS {
		t.Errorf("Layer() = %s, want L1", e.Layer())
	}
	if e.Step() != in.Step {
		t.Errorf("Step() = %q, want %q", e.Step(), in.Step)
	}
	if e.State() != StatePass {
		t.Errorf("State() = %s, want PASS", e.State())
	}
	if e.FailureClass() != FailureNone {
		t.Errorf("FailureClass() = %s, want NONE", e.FailureClass())
	}
	if !e.StartedAt().Equal(testStart) {
		t.Errorf("StartedAt() = %s, want %s", e.StartedAt(), testStart)
	}
	if e.Duration() != 12*time.Millisecond {
		t.Errorf("Duration() = %s, want 12ms", e.Duration())
	}
	if e.AttributeCount() != 2 {
		t.Errorf("AttributeCount() = %d, want 2", e.AttributeCount())
	}
	if e.IsZero() {
		t.Error("a constructed Evidence must not be zero")
	}

	v, ok := e.Attribute("dns.rcode")
	if !ok {
		t.Fatal("Attribute(dns.rcode) not found")
	}
	if got, _ := v.Str(); got != "NOERROR" {
		t.Errorf("attribute value = %q, want NOERROR", got)
	}
	if _, ok := e.Attribute("missing.key"); ok {
		t.Error("Attribute should report a missing key as absent")
	}
}

func TestNewEvidenceRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EvidenceInput)
	}{
		{"empty id", func(in *EvidenceInput) { in.ID = "" }},
		{"id with whitespace", func(in *EvidenceInput) { in.ID = "bad id\n" }},
		{"zero subject", func(in *EvidenceInput) { in.Subject = Subject{} }},
		{"unspecified layer", func(in *EvidenceInput) { in.Layer = LayerUnspecified }},
		{"out of range layer", func(in *EvidenceInput) { in.Layer = Layer(99) }},
		{"empty step", func(in *EvidenceInput) { in.Step = "" }},
		{"uppercase step", func(in *EvidenceInput) { in.Step = "DNS.Lookup" }},
		{"out of range state", func(in *EvidenceInput) { in.State = State(42) }},
		{"out of range failure class", func(in *EvidenceInput) {
			in.State = StateFail
			in.FailureClass = FailureClass(200)
		}},
		{"zero start time", func(in *EvidenceInput) { in.StartedAt = time.Time{} }},
		{"negative duration", func(in *EvidenceInput) { in.Duration = -time.Second }},
		{"invalid attribute key", func(in *EvidenceInput) {
			in.Attributes = map[AttributeKey]AttrValue{"DNS.RCode": StringAttr("NOERROR")}
		}},
		{"invalid attribute value", func(in *EvidenceInput) {
			in.Attributes = map[AttributeKey]AttrValue{"dns.rcode": {}}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInput(t)
			tt.mutate(&in)

			e, err := NewEvidence(in)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if !e.IsZero() {
				t.Error("a rejected input must return the zero Evidence")
			}
		})
	}
}

// TestStateFailureClassInvariants covers the two combinations that would make a
// report contradict itself, and confirms the rest stay permissive.
func TestStateFailureClassInvariants(t *testing.T) {
	tests := []struct {
		name    string
		state   State
		failure FailureClass
		wantErr bool
	}{
		{"pass with none", StatePass, FailureNone, false},
		{"pass with a failure class", StatePass, FailureTCPConnectionRefused, true},
		{"fail with a class", StateFail, FailureTCPConnectionRefused, false},
		{"fail without a class", StateFail, FailureNone, true},

		// The remaining states legitimately have classified and unclassified cases.
		{"degraded with none", StateDegraded, FailureNone, false},
		{"degraded with a class", StateDegraded, FailureTLSVersionMismatch, false},
		{"unknown with none", StateUnknown, FailureNone, false},
		{"unknown with local timeout", StateUnknown, FailureExecLocalTimeout, false},
		{"unknown with unsupported", StateUnknown, FailureExecUnsupportedBySvcdoctor, false},
		{"skipped with none", StateSkipped, FailureNone, false},
		{"skipped by policy", StateSkipped, FailureExecSkippedByPolicy, false},
		{"skipped after prerequisite", StateSkipped, FailureExecSkippedPrerequisiteFailed, false},
		{"skipped for privilege", StateSkipped, FailureExecInsufficientPrivilege, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInput(t)
			in.State = tt.state
			in.FailureClass = tt.failure

			_, err := NewEvidence(in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("err = %v, want ErrInvalidValue", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewEvidence: %v", err)
			}
		})
	}
}

// TestAttributesCopiedOnInput proves a caller cannot alter recorded evidence by
// reusing the map it passed in.
func TestAttributesCopiedOnInput(t *testing.T) {
	attrs := map[AttributeKey]AttrValue{"dns.rcode": StringAttr("NOERROR")}

	in := validInput(t)
	in.Attributes = attrs

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	attrs["dns.rcode"] = StringAttr("SERVFAIL")
	attrs["injected.key"] = BoolAttr(true)
	delete(attrs, "dns.rcode")

	v, ok := e.Attribute("dns.rcode")
	if !ok {
		t.Fatal("the recorded attribute disappeared with the caller's map")
	}
	if got, _ := v.Str(); got != "NOERROR" {
		t.Errorf("recorded value changed to %q", got)
	}
	if _, ok := e.Attribute("injected.key"); ok {
		t.Error("a key added to the caller's map appeared in recorded evidence")
	}
	if e.AttributeCount() != 1 {
		t.Errorf("AttributeCount() = %d, want 1", e.AttributeCount())
	}
}

// TestAttributesCopiedOnOutput proves a reader cannot alter recorded evidence
// through the map Attributes returns.
func TestAttributesCopiedOnOutput(t *testing.T) {
	in := validInput(t)
	in.Attributes = map[AttributeKey]AttrValue{"dns.rcode": StringAttr("NOERROR")}

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	first := e.Attributes()
	first["dns.rcode"] = StringAttr("SERVFAIL")
	first["injected.key"] = BoolAttr(true)

	second := e.Attributes()
	if got, _ := second["dns.rcode"].Str(); got != "NOERROR" {
		t.Errorf("recorded value changed to %q through a reader's map", got)
	}
	if _, ok := second["injected.key"]; ok {
		t.Error("a key added to a returned map appeared in recorded evidence")
	}
}

// TestStringListAttributeStaysIsolated checks the nested case: the slice inside
// an AttrValue must not be reachable for mutation either.
func TestStringListAttributeStaysIsolated(t *testing.T) {
	addrs := []string{"10.0.1.7", "10.0.1.8"}

	in := validInput(t)
	in.Attributes = map[AttributeKey]AttrValue{"dns.addresses": StringListAttr(addrs...)}

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	addrs[0] = "mutated"

	v, ok := e.Attribute("dns.addresses")
	if !ok {
		t.Fatal("attribute not found")
	}
	got, ok := v.StringList()
	if !ok {
		t.Fatal("attribute is not a string list")
	}
	if got[0] != "10.0.1.7" {
		t.Errorf("recorded list changed with the caller's slice: %q", got[0])
	}

	got[1] = "mutated"
	again, _ := v.StringList()
	if again[1] != "10.0.1.8" {
		t.Errorf("recorded list changed through a reader's slice: %q", again[1])
	}
}

func TestEvidenceNormalizesStartedAtToUTC(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*60*60)

	in := validInput(t)
	in.StartedAt = time.Date(2026, 8, 21, 13, 30, 0, 0, zone)

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	if got := e.StartedAt().Location(); got != time.UTC {
		t.Errorf("StartedAt location = %s, want UTC", got)
	}
	if !e.StartedAt().Equal(testStart) {
		t.Errorf("normalization changed the instant: %s", e.StartedAt())
	}
}

func TestEvidenceDropsMonotonicReading(t *testing.T) {
	in := validInput(t)
	in.StartedAt = time.Now()

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	got := e.StartedAt()
	if got != got.Round(0) {
		t.Error("the stored instant still carries a monotonic reading")
	}
}

func TestZeroDurationIsAccepted(t *testing.T) {
	in := validInput(t)
	in.Duration = 0

	if _, err := NewEvidence(in); err != nil {
		t.Fatalf("a zero duration should be accepted: %v", err)
	}
}

func TestEvidenceJSONPassing(t *testing.T) {
	in := validInput(t)
	in.Attributes = map[AttributeKey]AttrValue{"dns.rcode": StringAttr("NOERROR")}

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	got, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	const want = `{` +
		`"id":"target/ep:kafka.internal:9092/dns",` +
		`"subject":{"kind":"ENDPOINT","ref":"kafka.internal:9092"},` +
		`"layer":"L1",` +
		`"step":"dns.lookup",` +
		`"state":"PASS",` +
		`"attributes":{"dns.rcode":{"kind":"string","value":"NOERROR"}},` +
		`"startedAt":"2026-08-21T10:30:00Z",` +
		`"duration":"12ms"` +
		`}`
	if string(got) != want {
		t.Errorf("json.Marshal =\n%s\nwant\n%s", got, want)
	}
}

// TestEvidenceJSONOmitsEmptyFields pins that an absent failure class and an
// absent attribute set are omitted rather than encoded as "NONE" and "{}", so a
// reader is not shown fields that carry no information.
func TestEvidenceJSONOmitsEmptyFields(t *testing.T) {
	e, err := NewEvidence(validInput(t))
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	got, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, present := decoded["failureClass"]; present {
		t.Error("failureClass should be omitted when nothing failed")
	}
	if _, present := decoded["attributes"]; present {
		t.Error("attributes should be omitted when there are none")
	}
}

func TestEvidenceJSONFailing(t *testing.T) {
	in := validInput(t)
	in.ID = mustID(t, "target/ep:broker-2.internal:9092/dns")
	in.Subject = mustEndpointSubject(t, "broker-2.internal:9092")
	in.State = StateFail
	in.FailureClass = FailureDNSNXDomain
	in.Duration = 250 * time.Millisecond

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	got, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	const want = `{` +
		`"id":"target/ep:broker-2.internal:9092/dns",` +
		`"subject":{"kind":"ENDPOINT","ref":"broker-2.internal:9092"},` +
		`"layer":"L1",` +
		`"step":"dns.lookup",` +
		`"state":"FAIL",` +
		`"failureClass":"DNS_NXDOMAIN",` +
		`"startedAt":"2026-08-21T10:30:00Z",` +
		`"duration":"250ms"` +
		`}`
	if string(got) != want {
		t.Errorf("json.Marshal =\n%s\nwant\n%s", got, want)
	}
}

// TestEvidenceJSONIsDeterministic covers attribute ordering, which relies on
// encoding/json sorting map keys rather than on Go's randomized map iteration.
func TestEvidenceJSONIsDeterministic(t *testing.T) {
	in := validInput(t)
	in.Attributes = map[AttributeKey]AttrValue{
		"z.last":        IntAttr(3),
		"a.first":       StringAttr("one"),
		"m.middle":      BoolAttr(true),
		"dns.addresses": StringListAttr("10.0.1.7", "10.0.1.8"),
		"tcp.latency":   DurationAttr(5 * time.Millisecond),
	}

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	first, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(first) != string(again) {
			t.Fatalf("encoding differed between runs:\n%s\n%s", first, again)
		}
	}

	// Keys must come out sorted, not in insertion or hash order.
	var decoded struct {
		Attributes map[string]json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(decoded.Attributes) != 5 {
		t.Fatalf("got %d attributes, want 5", len(decoded.Attributes))
	}
	if !strings.Contains(string(first), `"attributes":{"a.first"`) {
		t.Errorf("attributes are not sorted; encoding was\n%s", first)
	}
}

// TestEvidenceJSONUsesSymbolicEnums guards against enum ordinals leaking into
// the report contract.
func TestEvidenceJSONUsesSymbolicEnums(t *testing.T) {
	in := validInput(t)
	in.State = StateSkipped
	in.FailureClass = FailureExecSkippedPrerequisiteFailed

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded struct {
		Layer        string `json:"layer"`
		State        string `json:"state"`
		FailureClass string `json:"failureClass"`
		Subject      struct {
			Kind string `json:"kind"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Layer != "L1" {
		t.Errorf("layer = %q, want L1", decoded.Layer)
	}
	if decoded.State != "SKIPPED" {
		t.Errorf("state = %q, want SKIPPED", decoded.State)
	}
	if decoded.FailureClass != "EXEC_SKIPPED_PREREQUISITE_FAILED" {
		t.Errorf("failureClass = %q", decoded.FailureClass)
	}
	if decoded.Subject.Kind != "ENDPOINT" {
		t.Errorf("subject kind = %q, want ENDPOINT", decoded.Subject.Kind)
	}
}

func TestZeroEvidenceIsInvalid(t *testing.T) {
	var e Evidence

	if !e.IsZero() {
		t.Error("the zero Evidence should report IsZero")
	}
	if e.String() != "<invalid evidence>" {
		t.Errorf("String() = %q, want %q", e.String(), "<invalid evidence>")
	}
	if e.AttributeCount() != 0 {
		t.Error("the zero Evidence should have no attributes")
	}
	if e.Attributes() != nil {
		t.Error("the zero Evidence should return no attribute map")
	}

	if _, err := json.Marshal(e); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

func TestEvidenceString(t *testing.T) {
	in := validInput(t)
	in.State = StateFail
	in.FailureClass = FailureDNSNXDomain

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	const want = "target/ep:kafka.internal:9092/dns L1 dns.lookup FAIL DNS_NXDOMAIN"
	if got := e.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestEvidenceCarriesNoInterpretation pins the boundary against diagnosis.
// Severity, confidence, recommendations and finding codes are interpretations,
// and interpretation is not evidence.
func TestEvidenceCarriesNoInterpretation(t *testing.T) {
	var e any = Evidence{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"Severity", hasMethod[interface{ Severity() string }](e)},
		{"Confidence", hasMethod[interface{ Confidence() string }](e)},
		{"Recommendations", hasMethod[interface{ Recommendations() []string }](e)},
		{"FindingCode", hasMethod[interface{ FindingCode() string }](e)},
		{"Parents", hasMethod[interface{ Parents() []EvidenceID }](e)},
		{"BlockedBy", hasMethod[interface{ BlockedBy() []EvidenceID }](e)},
		{"Origin", hasMethod[interface{ Origin() string }](e)},
		{"Err", hasMethod[interface{ Err() error }](e)},
		{"Raw", hasMethod[interface{ Raw() any }](e)},
	}

	for _, f := range forbidden {
		if f.has {
			t.Errorf("Evidence must not expose %s", f.name)
		}
	}
}

func hasMethod[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

func mustID(t *testing.T, s string) EvidenceID {
	t.Helper()
	id, err := NewEvidenceID(s)
	if err != nil {
		t.Fatalf("NewEvidenceID(%q): %v", s, err)
	}
	return id
}

func mustStep(t *testing.T, s string) Step {
	t.Helper()
	step, err := NewStep(s)
	if err != nil {
		t.Fatalf("NewStep(%q): %v", s, err)
	}
	return step
}
