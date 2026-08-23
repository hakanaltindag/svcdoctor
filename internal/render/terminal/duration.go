package terminal

import (
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// formatElapsed renders one step's elapsed time, or nothing when none was taken.
//
// # An unmeasured step and a measured zero are different rows
//
// A step that was never timed — a SKIPPED node, the requested-target anchor, an
// authentication svcdoctor declined to attempt — has no duration column at all.
// A step that ran and measured zero prints `0s`. The two used to be one blank
// cell, because domain.Evidence carried a bare time.Duration and both wrote zero
// into it; domain.Elapsed is what separates them, and this function is the only
// place the difference reaches a reader.
//
// It is the same discipline ADR 0052 applies one layer up: `not measured` is
// never collapsed into another outcome. Printing `0s` for a step that never ran
// would claim a measurement; printing nothing for a step that measured zero
// would discard one.
func formatElapsed(e domain.Elapsed) string {
	d, measured := e.Duration()
	if !measured {
		return ""
	}
	return formatDuration(d)
}

// formatDuration renders one measured elapsed time.
//
// # It says how long, and never what that means
//
// A duration here is wall-clock elapsed time for one attempted exchange, and
// that is the whole of the claim. This function has no threshold, no comparison,
// no ranking and no vocabulary for `slow`, `fast`, `degraded` or `high latency`.
// Deciding that 42ms is a problem is diagnosis, it would need a baseline this
// repository does not collect, and PostgreSQL BASIC is frozen with no latency
// finding in it.
//
// # Three scales, one decimal, deterministic
//
// Precision is capped so that the same duration always renders the same way and
// golden output does not churn on a machine that measured a hundred nanoseconds
// differently. Microseconds get no decimal because the last digit there is noise
// from the scheduler rather than a fact about the endpoint.
//
// # Zero renders `0s`, and it is a measurement
//
// A monotonic clock has a tick — about 41.67ns on Apple Silicon — and an
// operation that starts and ends inside one returns a zero interval. That is a
// real result and it is reported as one. Callers holding a domain.Elapsed use
// formatElapsed, which renders the *absence* of a measurement as an empty cell;
// this function is only ever given something that was measured.
func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d < time.Microsecond:
		return "<1µs"
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.1fs", float64(d)/float64(time.Second))
	}
}
