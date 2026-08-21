package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewRecommendation(t *testing.T) {
	const action = "Verify that advertised.listeners resolves from this network."

	r, err := NewRecommendation(action)
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	if r.Action() != action {
		t.Errorf("Action() = %q, want %q", r.Action(), action)
	}
	if r.IsZero() {
		t.Error("a constructed Recommendation must not be zero")
	}
	if r.String() != action {
		t.Errorf("String() = %q, want the action", r.String())
	}
}

func TestNewRecommendationRejects(t *testing.T) {
	tests := []struct {
		name   string
		action string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"leading space", " check the listener"},
		{"trailing space", "check the listener "},
		{"newline", "check the listener\n"},
		{"embedded newline", "check\nthe listener"},
		{"null byte", "check\x00listener"},
		{"invalid utf8", "check\xff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRecommendation(tt.action)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if !r.IsZero() {
				t.Error("a rejected action must return the zero Recommendation")
			}
		})
	}
}

func TestRecommendationJSON(t *testing.T) {
	r, err := NewRecommendation("Check the broker listener configuration.")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}

	got, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `{"action":"Check the broker listener configuration."}`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}

	// Deterministic across repeated encodings.
	for i := 0; i < 10; i++ {
		again, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(again) != string(got) {
			t.Fatalf("encoding varied: %s vs %s", again, got)
		}
	}
}

func TestZeroRecommendationIsInvalid(t *testing.T) {
	var r Recommendation

	if !r.IsZero() {
		t.Error("the zero Recommendation should report IsZero")
	}
	if r.String() != "<invalid recommendation>" {
		t.Errorf("String() = %q", r.String())
	}
	if _, err := json.Marshal(r); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal err = %v, want ErrInvalidValue", err)
	}
}

func TestRecommendationIsComparableValue(t *testing.T) {
	a, err := NewRecommendation("do the thing")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	b, err := NewRecommendation("do the thing")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	c, err := NewRecommendation("do another thing")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}

	if a != b {
		t.Error("identical recommendations should compare equal")
	}
	if a == c {
		t.Error("different recommendations should not compare equal")
	}
}

// TestRecommendationIsInert pins that a recommendation is report data, not
// something svcdoctor executes.
func TestRecommendationIsInert(t *testing.T) {
	var r any = Recommendation{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"Run", hasMethod[interface{ Run() error }](r)},
		{"Apply", hasMethod[interface{ Apply() error }](r)},
		{"Execute", hasMethod[interface{ Execute() error }](r)},
		{"Command", hasMethod[interface{ Command() string }](r)},
		{"Metadata", hasMethod[interface{ Metadata() map[string]any }](r)},
	}

	for _, f := range forbidden {
		if f.has {
			t.Errorf("Recommendation must not expose %s", f.name)
		}
	}
}
