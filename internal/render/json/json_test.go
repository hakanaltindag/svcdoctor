package json

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// report builds a minimal but genuine report through the ordinary domain
// constructors, so every invariant the report enforces is in force here too.
func report(t *testing.T) domain.Report {
	t.Helper()

	service, err := domain.NewServiceID("postgres")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-test", time.Unix(0, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("db.internal:5432", "db.internal:5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("svcdoctor-test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	subject, err := domain.NewEndpointSubject("db.internal:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:        "dns.lookup/db.internal",
		Subject:   subject,
		Layer:     domain.LayerDNS,
		Step:      "dns.lookup",
		State:     domain.StatePass,
		StartedAt: time.Unix(0, 0).UTC(),
		Elapsed:   domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	built, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return built
}

// TestWriteEmitsTheCanonicalReport proves this package adds nothing.
//
// The bytes must equal the report's own marshalling exactly, because that is
// what "canonical" means: a second encoder here would be a second schema to keep
// in step with (ADR 0016).
func TestWriteEmitsTheCanonicalReport(t *testing.T) {
	r := report(t)

	canonical, err := stdjson.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var out bytes.Buffer
	if err := Write(&out, r); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if got := bytes.TrimSuffix(out.Bytes(), []byte("\n")); !bytes.Equal(got, canonical) {
		t.Errorf("the written document is not the canonical report\n got: %s\nwant: %s",
			got, canonical)
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
		t.Error("the document does not end with a newline")
	}
	if bytes.Count(out.Bytes(), []byte("\n")) != 1 {
		t.Error("the document is not a single line followed by one newline")
	}
}

// TestWriteInventsNoFields is the wrapper prohibition, checked structurally.
func TestWriteInventsNoFields(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, report(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var decoded map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	want := map[string]bool{
		"schemaVersion": true, "run": true, "target": true, "vantage": true,
		"evidence": true, "findings": true, "summary": true, "security": true,
	}
	for key := range decoded {
		if !want[key] {
			t.Errorf("unexpected top-level key %q; the artifact is the report alone", key)
		}
	}
	for key := range want {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
	// The three fields ADR 0048 names as forbidden, checked by name so that
	// adding one has to delete this test.
	for _, invented := range []string{"report", "incomplete", "exitCode", "sessionEstablished"} {
		if _, ok := decoded[invented]; ok {
			t.Errorf("the artifact carries %q", invented)
		}
	}

	var schemaVersion int
	if err := stdjson.Unmarshal(decoded["schemaVersion"], &schemaVersion); err != nil {
		t.Fatalf("schemaVersion: %v", err)
	}
	if schemaVersion != domain.SchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", schemaVersion, domain.SchemaVersion)
	}
}

// TestWriteIsDeterministic pins the property automation depends on.
func TestWriteIsDeterministic(t *testing.T) {
	r := report(t)
	var first, second bytes.Buffer
	if err := Write(&first, r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Write(&second, r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("the same report produced different bytes")
	}
}

// TestWriteEmitsNothingOnFailure proves a report that cannot be encoded leaves
// no half-artifact behind for a pipeline to parse.
func TestWriteEmitsNothingOnFailure(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, domain.Report{}); err == nil {
		t.Fatal("the zero report encoded successfully")
	}
	if out.Len() != 0 {
		t.Errorf("wrote %q after a failed encoding", out.String())
	}
}

// failingWriter reports an error after accepting nothing.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }

func TestWriteReportsAWriteFailure(t *testing.T) {
	if err := Write(failingWriter{}, report(t)); err == nil {
		t.Error("a failed write was reported as success")
	}
	if err := Write(nil, report(t)); err == nil {
		t.Error("a nil writer was accepted")
	}
}
