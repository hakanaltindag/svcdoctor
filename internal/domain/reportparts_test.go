package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewServiceID(t *testing.T) {
	for _, s := range []string{"kafka", "postgres", "redis", "mysql", "opensearch", "svc_2"} {
		id, err := NewServiceID(s)
		if err != nil {
			t.Fatalf("NewServiceID(%q): %v", s, err)
		}
		if id.String() != s || !id.Valid() {
			t.Errorf("round trip failed for %q", s)
		}
	}

	for _, s := range []string{"", "Kafka", "KAFKA", "kafka-broker", "kafka.broker", "kafka ", " kafka"} {
		if _, err := NewServiceID(s); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("NewServiceID(%q) err = %v, want ErrInvalidValue", s, err)
		}
	}
}

// TestServiceIDSetIsOpen pins that validation checks shape, never a list of
// known services. A future service must not require editing core validation.
func TestServiceIDSetIsOpen(t *testing.T) {
	for _, s := range []string{"cassandra", "nats", "somethingnobodyplanned"} {
		if _, err := NewServiceID(s); err != nil {
			t.Errorf("an unknown service must still be accepted: %q: %v", s, err)
		}
	}
}

func TestNewTarget(t *testing.T) {
	tgt, err := NewTarget("kafka.internal:9092", "broker-1.internal:9092", "broker-2.internal:9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	if tgt.Requested() != "kafka.internal:9092" {
		t.Errorf("Requested() = %q", tgt.Requested())
	}
	if got := tgt.Normalized(); len(got) != 2 {
		t.Errorf("Normalized() = %v", got)
	}
	if tgt.IsZero() {
		t.Error("a constructed Target must not be zero")
	}
}

func TestTargetNormalizedIsOptional(t *testing.T) {
	tgt, err := NewTarget("kafka.internal:9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if tgt.Normalized() != nil {
		t.Error("Normalized() should be nil when none was supplied")
	}

	raw, err := json.Marshal(tgt)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(raw), "normalized") {
		t.Errorf("an absent normalized list should be omitted: %s", raw)
	}
}

func TestTargetRejects(t *testing.T) {
	if _, err := NewTarget(""); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("empty request: err = %v", err)
	}
	if _, err := NewTarget("host", ""); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("empty normalized entry: err = %v", err)
	}
	if _, err := NewTarget("host\n"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("control char: err = %v", err)
	}
}

func TestTargetIsImmutable(t *testing.T) {
	normalized := []string{"broker-1.internal:9092"}

	tgt, err := NewTarget("kafka.internal:9092", normalized...)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	normalized[0] = "mutated"
	if got := tgt.Normalized(); got[0] != "broker-1.internal:9092" {
		t.Errorf("target changed with the caller's slice: %q", got[0])
	}

	out := tgt.Normalized()
	out[0] = "mutated"
	if got := tgt.Normalized(); got[0] != "broker-1.internal:9092" {
		t.Errorf("target changed through a returned slice: %q", got[0])
	}
}

// TestTargetAcceptsNoSecretTypes pins the security boundary structurally: there
// is no field through which credential material could arrive intact.
func TestTargetAcceptsNoSecretTypes(t *testing.T) {
	var tgt any = Target{}

	if _, ok := tgt.(interface{ Credential() string }); ok {
		t.Error("Target must not expose a credential")
	}
	if _, ok := tgt.(interface{ Metadata() map[string]any }); ok {
		t.Error("Target must not carry an arbitrary metadata bag")
	}
}

func TestNewRunMetadata(t *testing.T) {
	started := time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

	run, err := NewRunMetadata("0.1.0", started, 1500*time.Millisecond, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}

	if run.SvcdoctorVersion() != "0.1.0" {
		t.Errorf("SvcdoctorVersion() = %q", run.SvcdoctorVersion())
	}
	if !run.StartedAt().Equal(started) {
		t.Errorf("StartedAt() = %s", run.StartedAt())
	}
	if run.Duration() != 1500*time.Millisecond {
		t.Errorf("Duration() = %s", run.Duration())
	}
	if run.Service() != "kafka" {
		t.Errorf("Service() = %q", run.Service())
	}
	if run.IsZero() {
		t.Error("a constructed RunMetadata must not be zero")
	}
}

func TestRunMetadataRejects(t *testing.T) {
	started := time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name     string
		version  string
		started  time.Time
		duration time.Duration
		service  ServiceID
	}{
		{"empty version", "", started, time.Second, "kafka"},
		{"zero start time", "0.1.0", time.Time{}, time.Second, "kafka"},
		{"negative duration", "0.1.0", started, -time.Second, "kafka"},
		{"empty service", "0.1.0", started, time.Second, ""},
		{"invalid service", "0.1.0", started, time.Second, "Kafka"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, err := NewRunMetadata(tt.version, tt.started, tt.duration, tt.service)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if !run.IsZero() {
				t.Error("a rejected input must return the zero RunMetadata")
			}
		})
	}
}

func TestRunMetadataNormalizesToUTC(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*60*60)
	local := time.Date(2026, 8, 21, 13, 30, 0, 0, zone)

	run, err := NewRunMetadata("0.1.0", local, time.Second, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	if run.StartedAt().Location() != time.UTC {
		t.Errorf("StartedAt location = %s, want UTC", run.StartedAt().Location())
	}
}

// TestRunMetadataPerformsNoDiscovery pins that every value is caller-supplied.
// A method that worked something out for itself would be hidden I/O in a value
// type.
func TestRunMetadataPerformsNoDiscovery(t *testing.T) {
	var r any = RunMetadata{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"DetectVersion", hasMethod[interface{ DetectVersion() string }](r)},
		{"Hostname", hasMethod[interface{ Hostname() string }](r)},
		{"Args", hasMethod[interface{ Args() []string }](r)},
		{"Environment", hasMethod[interface{ Environment() map[string]string }](r)},
	}
	for _, f := range forbidden {
		if f.has {
			t.Errorf("RunMetadata must not expose %s", f.name)
		}
	}
}

func TestNewReportSecurity(t *testing.T) {
	sec, err := NewReportSecurity(OutputModeLocalFull, true, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	if sec.OutputMode() != OutputModeLocalFull {
		t.Errorf("OutputMode() = %s", sec.OutputMode())
	}
	if !sec.TLSVerificationDisabled() {
		t.Error("TLSVerificationDisabled() = false, want true")
	}
	if sec.CredentialForwardingEnabled() {
		t.Error("CredentialForwardingEnabled() = true, want false")
	}
}

// TestShareableModeIsRefusedUntilRedactionExists is the honesty guarantee. A
// report labelled shareable asserts that sensitive values were removed. Nothing
// removes them yet, so the label must be unavailable rather than aspirational.
func TestShareableModeIsRefusedUntilRedactionExists(t *testing.T) {
	sec, err := NewReportSecurity(OutputModeShareableRedacted, false, false)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err = %v, want ErrInvalidValue", err)
	}
	if !sec.IsZero() {
		t.Error("a rejected mode must return the zero ReportSecurity")
	}
	if !strings.Contains(err.Error(), "redaction") {
		t.Errorf("the error should explain why: %v", err)
	}

	// The vocabulary still exists, so the encoded shape is stable and enabling
	// the mode later is a one-line change.
	if !OutputModeShareableRedacted.Valid() {
		t.Error("the shareable mode should remain a defined value")
	}
}

// TestReportSecurityReportsNoFabricatedRedactionCounts pins that fields which
// could only hold invented values are absent, rather than present and zero.
func TestReportSecurityReportsNoFabricatedRedactionCounts(t *testing.T) {
	sec, err := NewReportSecurity(OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	raw, err := json.Marshal(sec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, absent := range []string{"redactedFields", "redactedCategories", "redactionCount"} {
		if strings.Contains(string(raw), absent) {
			t.Errorf("%q must not appear until redaction exists: %s", absent, raw)
		}
	}

	var s any = sec
	if _, ok := s.(interface{ Redact() error }); ok {
		t.Error("ReportSecurity must not perform redaction")
	}
}

func TestReportSecurityJSON(t *testing.T) {
	sec, err := NewReportSecurity(OutputModeLocalFull, false, true)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	got, err := json.Marshal(sec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `{"outputMode":"LOCAL_FULL","tlsVerificationDisabled":false,` +
		`"credentialForwardingEnabled":true}`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}

func TestOutputModeNamesCoverAllModes(t *testing.T) {
	const wantCount = 3 // unspecified plus two modes

	if len(outputModeNames) != wantCount {
		t.Fatalf("outputModeNames has %d entries, want %d", len(outputModeNames), wantCount)
	}
	if OutputModeUnspecified.Valid() {
		t.Error("the zero OutputMode must not be valid")
	}
	if _, err := json.Marshal(OutputModeUnspecified); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("marshalling an unspecified mode: err = %v", err)
	}
}

func TestSummaryStatusNamesCoverAllValues(t *testing.T) {
	const wantCount = 3 // unspecified, ok, problems found

	if len(summaryStatusNames) != wantCount {
		t.Fatalf("summaryStatusNames has %d entries, want %d", len(summaryStatusNames), wantCount)
	}
	if SummaryStatusUnspecified.Valid() {
		t.Error("the zero SummaryStatus must not be valid")
	}
	if got := SummaryStatus(99).String(); got != "SummaryStatus(99)" {
		t.Errorf("String() = %q", got)
	}
}
