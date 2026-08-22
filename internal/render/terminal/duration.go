package terminal

import (
	"fmt"
	"time"
)

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
// A zero duration renders empty. Zero means no work was timed — a SKIPPED node,
// or the anchor — and printing `0s` would invite a reader to think something was
// measured and took no time.
func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
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
