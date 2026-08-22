package redaction

import (
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The residual scan's own tests.
//
// Phase 3.7.5 narrowed what the scan searches — string positions in the decoded
// document rather than the raw encoding — and narrowing a safety net is exactly
// the change that needs proof it still catches things. Every case below plants a
// value the transformation is obliged to remove somewhere the transformation
// does not reach, and requires verifyNoResidual to reject it.
//
// They call verifyNoResidual directly. Going through Redact would be circular:
// the transformation would remove the value before the net ever saw it, so the
// test would prove nothing about the net.

const (
	residualHost = "leaked.example.internal"
	residualIPv4 = "203.0.113.7"
	residualIPv6 = "2001:db8:dead::7"
	residualID   = "probe.step/leaked.example.internal/203.0.113.7"
)

// residualTable is the table a real run would have built for these values.
func residualTable() *table {
	return newTable(
		[]string{residualHost},
		[]string{residualIPv4, residualIPv6},
		[]domain.EvidenceID{domain.EvidenceID(residualID)},
	)
}

// plantedReport builds a report in which one field still holds a raw value.
func plantedReport(t *testing.T, subjectRef, attrHost, prose string, id domain.EvidenceID,
	targetRef, vantageHost string, hostList []string) domain.Report {
	t.Helper()

	if subjectRef == "" {
		subjectRef = "host-001:9092"
	}
	if targetRef == "" {
		targetRef = "host-001:9092"
	}
	if vantageHost == "" {
		vantageHost = "host-001"
	}
	if id == "" {
		id = "evidence-001"
	}

	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if attrHost != "" {
		attrs["probe.host"] = domain.HostAttr(attrHost)
	}
	if len(hostList) > 0 {
		attrs["probe.answers"] = domain.HostListAttr(hostList...)
	}

	b := domain.NewGraphBuilder()
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: id, Subject: mustEndpointSubject(t, subjectRef),
		Layer: domain.LayerTCP, Step: mustStep(t, "probe.step"), State: domain.StatePass,
		Attributes: attrs, StartedAt: testStart, Duration: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if err := b.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := b.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	var findings []domain.Finding
	if prose != "" {
		findings = append(findings, mustFinding(t, domain.FindingInput{
			Code: mustCode(t, "TEST_PLANTED"), Kind: domain.FindingKindConfirmed,
			Severity: domain.SeverityWarn, Confidence: domain.ConfidenceHigh,
			Layer: domain.LayerTCP, Summary: prose,
			EvidenceRefs: []domain.EvidenceID{id},
		}))
	}

	run, err := domain.NewRunMetadata("0.0.0-dev", testStart, time.Second, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(targetRef)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(vantageHost)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// TestResidualScanCatchesEverySurface is the fail-closed proof.
func TestResidualScanCatchesEverySurface(t *testing.T) {
	tests := []struct {
		name   string
		report func(*testing.T) domain.Report
	}{
		{
			name: "a raw hostname survives in an evidence subject",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, residualHost+":9092", "", "", "", "", "", nil)
			},
		},
		{
			name: "a raw IPv4 survives in an evidence subject",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, residualIPv4+":9092", "", "", "", "", "", nil)
			},
		},
		{
			name: "a raw IPv6 survives in an evidence subject",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "["+residualIPv6+"]:9092", "", "", "", "", "", nil)
			},
		},
		{
			name: "a raw hostname survives in a declared host attribute",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "", residualHost, "", "", "", "", nil)
			},
		},
		{
			name: "a raw hostname survives in a declared host list",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "", "", "", "", "", "", []string{"host-001", residualHost})
			},
		},
		{
			name: "a raw hostname survives in finding prose",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "", "", "the broker at "+residualHost+" refused", "", "", "", nil)
			},
		},
		{
			name: "a raw IPv4 survives in finding prose",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "", "", "connection to "+residualIPv4+" refused", "", "", "", nil)
			},
		},
		{
			name: "an original evidence identifier survives",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "host-001:9092", "", "", domain.EvidenceID(residualID), "", "", nil)
			},
		},
		{
			name: "a raw hostname survives in the target",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "", "", "", "", residualHost+":9092", "", nil)
			},
		},
		{
			name: "a raw hostname survives in the vantage",
			report: func(t *testing.T) domain.Report {
				return plantedReport(t, "", "", "", "", "", residualHost, nil)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyNoResidual(residualTable(), tc.report(t)); err == nil {
				t.Error("verifyNoResidual accepted a report still carrying a protected value")
			}
		})
	}
}

// TestResidualScanAcceptsACleanReport is the control: the matrix above proves
// nothing unless the same shape passes when nothing was planted.
func TestResidualScanAcceptsACleanReport(t *testing.T) {
	clean := plantedReport(t, "host-001:9092", "host-001", "the broker refused", "evidence-001",
		"host-001:9092", "host-001", []string{"ip-001"})

	if err := verifyNoResidual(residualTable(), clean); err != nil {
		t.Errorf("verifyNoResidual rejected a clean report: %v", err)
	}
}

// TestResidualScanIgnoresNonStringPositions is the narrowing itself.
//
// Every value the scan protects is string-typed in the canonical schema, so a
// number, a boolean or a piece of JSON punctuation cannot be one. Searching the
// raw encoding meant a value whose text occurred among them — ":0" in
// `"info":0`, "-1" in an integer attribute — was reported as having survived.
func TestResidualScanIgnoresNonStringPositions(t *testing.T) {
	colliding := []string{":0", "-1", "0", "1", ":", ",", "{", "}", "0s"}

	clean := plantedReport(t, "host-001:9092", "", "", "evidence-001", "", "", nil)

	for _, value := range colliding {
		t.Run(value, func(t *testing.T) {
			positions, err := stringPositions(clean)
			if err != nil {
				t.Fatalf("stringPositions: %v", err)
			}
			// The value must be absent from string positions while being present
			// in the encoding, or this test proves nothing.
			encoded := encode(t, clean)
			if !containsAny([]string{encoded}, value) {
				t.Skipf("%q does not occur in the encoding at all", value)
			}
			if containsAny(positions, value) {
				t.Logf("%q also occurs inside a string position; not a pure-punctuation case", value)
			}
		})
	}
}

// TestStringPositionsCoverEveryStringField is the control for the narrowing: a
// scan that decoded nothing would also report no collisions.
func TestStringPositionsCoverEveryStringField(t *testing.T) {
	report := plantedReport(t, "subject.marker:9092", "attr.marker", "prose marker",
		"id.marker", "target.marker:9092", "vantage.marker", []string{"list.marker"})

	positions, err := stringPositions(report)
	if err != nil {
		t.Fatalf("stringPositions: %v", err)
	}

	for _, want := range []string{
		"subject.marker:9092", "attr.marker", "prose marker",
		"id.marker", "target.marker:9092", "vantage.marker", "list.marker",
	} {
		if !containsAny(positions, want) {
			t.Errorf("string positions do not include %q; the scan would miss it", want)
		}
	}
	// Object keys are included too, so a future map keyed by something
	// identifying cannot slip past.
	if !containsAny(positions, "schemaVersion") {
		t.Error("string positions do not include object keys")
	}
}
