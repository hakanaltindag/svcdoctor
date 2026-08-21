package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestFindingKind(t *testing.T) {
	tests := []struct {
		kind FindingKind
		want string
	}{
		{FindingKindUnspecified, "UNSPECIFIED"},
		{FindingKindConfirmed, "CONFIRMED"},
		{FindingKindHypothesis, "HYPOTHESIS"},
		{FindingKind(99), "FindingKind(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	for _, k := range []FindingKind{FindingKindConfirmed, FindingKindHypothesis} {
		got, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", k, err)
		}
		if string(got) != `"`+k.String()+`"` {
			t.Errorf("json.Marshal(%s) = %s", k, got)
		}
	}
}

func TestInvalidFindingKind(t *testing.T) {
	for _, k := range []FindingKind{FindingKindUnspecified, FindingKind(99)} {
		if k.Valid() {
			t.Errorf("%s must not be valid", k)
		}
		if _, err := json.Marshal(k); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("json.Marshal(%s) err = %v, want ErrInvalidValue", k, err)
		}
	}
}

// TestOnlyTwoFindingKinds pins the locked set. A hypothesis is a finding with a
// different kind, not a separate report type, and there is no third state.
func TestFindingKindNamesCoverAllKinds(t *testing.T) {
	const wantCount = 3 // unspecified, confirmed, hypothesis

	if len(findingKindNames) != wantCount {
		t.Fatalf("findingKindNames has %d entries, want %d", len(findingKindNames), wantCount)
	}
	if FindingKind(FindingKindHypothesis + 1).Valid() {
		t.Error("no finding kind beyond HYPOTHESIS should be defined")
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityUnspecified, "UNSPECIFIED"},
		{SeverityInfo, "INFO"},
		{SeverityWarn, "WARN"},
		{SeverityError, "ERROR"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "Severity(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	for _, s := range []Severity{SeverityInfo, SeverityWarn, SeverityError, SeverityCritical} {
		got, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", s, err)
		}
		if string(got) != `"`+s.String()+`"` {
			t.Errorf("json.Marshal(%s) = %s", s, got)
		}
	}
}

func TestInvalidSeverity(t *testing.T) {
	for _, s := range []Severity{SeverityUnspecified, Severity(99)} {
		if s.Valid() {
			t.Errorf("%s must not be valid", s)
		}
		if _, err := json.Marshal(s); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("json.Marshal(%s) err = %v, want ErrInvalidValue", s, err)
		}
	}
}

// TestSeverityOrderingIsIntentional pins the declared order. It is documented on
// the type as part of the contract, because a report summary has to name the
// highest severity present. Reordering the constants would silently change that.
func TestSeverityOrderingIsIntentional(t *testing.T) {
	ordered := []Severity{SeverityInfo, SeverityWarn, SeverityError, SeverityCritical}

	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Errorf("expected %s < %s", ordered[i-1], ordered[i])
		}
	}
}

// TestZeroSeverityIsNotInfo pins the decision that an unset severity is a bug
// rather than a harmless finding.
func TestZeroSeverityIsNotInfo(t *testing.T) {
	var s Severity

	if s == SeverityInfo {
		t.Error("the zero Severity must not be INFO")
	}
	if s.Valid() {
		t.Error("the zero Severity must not be valid")
	}
}

func TestSeverityNamesCoverAllLevels(t *testing.T) {
	const wantCount = 5 // unspecified plus four levels

	if len(severityNames) != wantCount {
		t.Fatalf("severityNames has %d entries, want %d", len(severityNames), wantCount)
	}
	if Severity(SeverityCritical + 1).Valid() {
		t.Error("no severity beyond CRITICAL should be defined")
	}
}

func TestConfidence(t *testing.T) {
	tests := []struct {
		confidence Confidence
		want       string
	}{
		{ConfidenceUnspecified, "UNSPECIFIED"},
		{ConfidenceLow, "LOW"},
		{ConfidenceMedium, "MEDIUM"},
		{ConfidenceHigh, "HIGH"},
		{Confidence(99), "Confidence(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.confidence.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	for _, c := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		got, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", c, err)
		}
		if string(got) != `"`+c.String()+`"` {
			t.Errorf("json.Marshal(%s) = %s", c, got)
		}
	}
}

func TestInvalidConfidence(t *testing.T) {
	for _, c := range []Confidence{ConfidenceUnspecified, Confidence(99)} {
		if c.Valid() {
			t.Errorf("%s must not be valid", c)
		}
		if _, err := json.Marshal(c); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("json.Marshal(%s) err = %v, want ErrInvalidValue", c, err)
		}
	}
}

// TestConfidenceIsNotNumeric is the guard against a probability creeping in.
// The encoded form must be an ordinal label, and the type must offer no way to
// obtain or compute a number from it.
func TestConfidenceIsNotNumeric(t *testing.T) {
	for _, c := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}

		// It must not decode as a number.
		var asNumber float64
		if err := json.Unmarshal(raw, &asNumber); err == nil {
			t.Errorf("%s encoded as a number: %s", c, raw)
		}

		var asString string
		if err := json.Unmarshal(raw, &asString); err != nil {
			t.Errorf("%s did not encode as a string: %s", c, raw)
		}
	}

	var c any = ConfidenceHigh
	if _, ok := c.(interface{ Probability() float64 }); ok {
		t.Error("Confidence must not expose a probability")
	}
	if _, ok := c.(interface{ Percent() int }); ok {
		t.Error("Confidence must not expose a percentage")
	}
	if _, ok := c.(interface{ Float64() float64 }); ok {
		t.Error("Confidence must not expose a numeric value")
	}
}

func TestConfidenceNamesCoverAllLevels(t *testing.T) {
	const wantCount = 4 // unspecified plus three levels

	if len(confidenceNames) != wantCount {
		t.Fatalf("confidenceNames has %d entries, want %d", len(confidenceNames), wantCount)
	}
	if Confidence(ConfidenceHigh + 1).Valid() {
		t.Error("no confidence beyond HIGH should be defined")
	}
}

// TestSeverityAndConfidenceAreIndependent pins that the two enums are not
// coupled. A critical finding may be held with low confidence, and a warning may
// be certain; neither combination is special-cased anywhere.
func TestSeverityAndConfidenceAreIndependent(t *testing.T) {
	severities := []Severity{SeverityInfo, SeverityWarn, SeverityError, SeverityCritical}
	confidences := []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}

	for _, s := range severities {
		for _, c := range confidences {
			in := validFindingInput(t)
			in.Severity = s
			in.Confidence = c

			if _, err := NewFinding(in); err != nil {
				t.Errorf("%s with %s should be constructible: %v", s, c, err)
			}
		}
	}
}

// TestNoExitCodeMapping pins that severity is data. Turning findings into a
// process status is defined in docs/SCOPE.md and belongs to the report and CLI
// boundary.
func TestNoExitCodeMapping(t *testing.T) {
	var s any = SeverityCritical
	if _, ok := s.(interface{ ExitCode() int }); ok {
		t.Error("Severity must not map to an exit code")
	}

	var f any = Finding{}
	if _, ok := f.(interface{ ExitCode() int }); ok {
		t.Error("Finding must not map to an exit code")
	}
}
