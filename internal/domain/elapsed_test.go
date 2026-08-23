package domain

import (
	"testing"
	"time"
)

// The Elapsed contract, stated directly rather than only through Evidence.
//
// Every consumer reads this type through Evidence.Elapsed, so it is tempting to
// test it only there. That leaves IsMeasured reachable by no assertion at all —
// measured by mutation: replacing its body with `e.d > 0` survived the whole
// suite, because every test that called it did so on an unmeasured value where
// both bodies agree. The measured-zero case is the one that separates them and
// it is the case this type exists for.

func TestElapsedRecordsMeasurementSeparatelyFromValue(t *testing.T) {
	tests := []struct {
		name         string
		in           Elapsed
		wantDuration time.Duration
		wantMeasured bool
	}{
		{"measured positive", Measured(12 * time.Millisecond), 12 * time.Millisecond, true},
		{"measured sub-tick", Measured(41 * time.Nanosecond), 41 * time.Nanosecond, true},
		{"measured zero", Measured(0), 0, true},
		{"unmeasured", Unmeasured(), 0, false},
		{"the zero value is unmeasured", Elapsed{}, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, measured := tt.in.Duration()
			if d != tt.wantDuration {
				t.Errorf("Duration() = %s, want %s", d, tt.wantDuration)
			}
			if measured != tt.wantMeasured {
				t.Errorf("Duration() measured = %t, want %t", measured, tt.wantMeasured)
			}
			if got := tt.in.IsMeasured(); got != tt.wantMeasured {
				t.Errorf("IsMeasured() = %t, want %t", got, tt.wantMeasured)
			}
		})
	}
}

// TestAMeasuredZeroIsNotTheZeroValue is the distinction, on its own.
//
// Elapsed is comparable, so this is also what stops a caller reconstructing the
// old ambiguity with ==: the two values differ even though both carry zero.
func TestAMeasuredZeroIsNotTheZeroValue(t *testing.T) {
	if Measured(0) == Unmeasured() {
		t.Error("a measured zero compares equal to no measurement")
	}
	if !Measured(0).IsMeasured() {
		t.Error("a measured zero reports itself unmeasured")
	}
	if Unmeasured().IsMeasured() {
		t.Error("an absent measurement reports itself measured")
	}
}

// TestElapsedIsAValue pins that a recorded measurement cannot be edited through
// anything Elapsed hands out. Both fields are unexported and there is no setter,
// so a copy is the only way to a different value.
func TestElapsedIsAValue(t *testing.T) {
	original := Measured(5 * time.Millisecond)
	copied := Measured(9 * time.Millisecond)

	if d, _ := original.Duration(); d != 5*time.Millisecond {
		t.Errorf("the original changed to %s", d)
	}
	if d, _ := copied.Duration(); d != 9*time.Millisecond {
		t.Errorf("the copy = %s, want 9ms", d)
	}
}
