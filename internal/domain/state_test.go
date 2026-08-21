package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateUnknown, "UNKNOWN"},
		{StatePass, "PASS"},
		{StateFail, "FAIL"},
		{StateDegraded, "DEGRADED"},
		{StateSkipped, "SKIPPED"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStateJSON(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateUnknown, `"UNKNOWN"`},
		{StatePass, `"PASS"`},
		{StateFail, `"FAIL"`},
		{StateDegraded, `"DEGRADED"`},
		{StateSkipped, `"SKIPPED"`},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			got, err := json.Marshal(tt.state)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestStateZeroValueIsUnknown pins the decision that an unset state reads as
// "could not be determined" rather than as a result.
func TestStateZeroValueIsUnknown(t *testing.T) {
	var s State

	if s != StateUnknown {
		t.Errorf("zero State = %d, want StateUnknown", s)
	}
	if !s.Valid() {
		t.Error("StateUnknown must be a valid state")
	}
	if s.String() != "UNKNOWN" {
		t.Errorf("zero State String() = %q, want %q", s.String(), "UNKNOWN")
	}
}

// TestInvalidStateIsNotPass is the safety property: an out-of-range value must
// never be mistaken for a passing result, and must not enter the report.
func TestInvalidStateIsNotPass(t *testing.T) {
	invalid := State(42)

	if invalid.Valid() {
		t.Error("State(42) must not be valid")
	}
	if invalid == StatePass {
		t.Error("an invalid state must never equal StatePass")
	}
	if got := invalid.String(); got != "State(42)" {
		t.Errorf("String() = %q, want %q", got, "State(42)")
	}

	_, err := json.Marshal(invalid)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

// TestUnknownAndSkippedAreDistinctFromPass guards the rule that "I could not
// measure it" and "it works" are different claims.
func TestUnknownAndSkippedAreDistinctFromPass(t *testing.T) {
	for _, s := range []State{StateUnknown, StateSkipped} {
		if s == StatePass {
			t.Errorf("%s must not equal StatePass", s)
		}
		if s == StateFail {
			t.Errorf("%s must not equal StateFail", s)
		}
	}
	if StateUnknown == StateSkipped {
		t.Error("StateUnknown and StateSkipped must remain distinct")
	}
}

// TestStateNamesCoverAllStates fails if a state is added without a name.
func TestStateNamesCoverAllStates(t *testing.T) {
	const wantCount = 5

	if len(stateNames) != wantCount {
		t.Fatalf("stateNames has %d entries, want %d", len(stateNames), wantCount)
	}
	for i, name := range stateNames {
		if name == "" {
			t.Errorf("State(%d) has no name", i)
		}
	}
}
