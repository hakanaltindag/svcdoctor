package domain

import "time"

// Elapsed is how long one step took, or the recorded fact that nothing was
// timed.
//
// # Why a zero duration could not carry both meanings
//
// Every evidence node used to hold a bare time.Duration, and two different facts
// wrote zero into it. A step that was never run — a SKIPPED node, the
// requested-target anchor, an authentication svcdoctor declined to attempt —
// has no elapsed time to report. And a step that *was* timed can genuinely
// measure zero: a monotonic clock has a tick, and an operation that completes
// inside one tick returns a zero interval. Measured on Apple Silicon, whose tick
// is about 41.67ns, a DNS lookup against an in-memory resolver returns zero
// often enough to make rendered output nondeterministic.
//
// So zero meant both "instant" and "never happened", and nothing downstream
// could tell which. ADR 0052 already fixed the principle that `not measured`
// must never be collapsed into another outcome; this is that same collapse one
// layer below the outcome vocabulary, and this type is what stops it.
//
// # The zero value is the safe one
//
// The zero Elapsed is unmeasured, which is the claim that asserts least. A
// producer that forgets to record a measurement under-reports; it cannot invent
// one.
//
// # It is a measurement, never an interpretation
//
// There is no comparison, no threshold, no "slow" and no ranking here. Deciding
// that a duration is a problem needs a baseline this repository does not
// collect, and no latency finding exists or is authorized.
type Elapsed struct {
	d time.Duration

	// measured is what separates the two facts above. It is unexported and
	// there is no setter, so an Elapsed cannot acquire or lose its measurement
	// after construction.
	measured bool
}

// Measured records a completed measurement of d.
//
// A zero d is a legitimate measurement and is preserved as one: the step ran and
// the clock could not separate its start from its end. That is a different fact
// from Unmeasured and renders differently.
//
// A negative d is not rejected here, because Elapsed has no error channel and a
// constructor that could fail would push a second error path into every probe.
// NewEvidence rejects it, which is the boundary that already validates
// everything else about a node.
func Measured(d time.Duration) Elapsed { return Elapsed{d: d, measured: true} }

// Unmeasured records that no timing was taken.
//
// It is the zero Elapsed, spelled out. A call site writing this is stating that
// the step produced no measurement, which a reader can check against what the
// step did; leaving the field out entirely would say the same thing silently.
func Unmeasured() Elapsed { return Elapsed{} }

// Duration returns the measured elapsed time and whether one was measured.
//
// The comma-ok shape is deliberate. A caller cannot read the duration without
// also receiving the answer to "was anything timed", which is exactly the
// question the old bare time.Duration let everyone skip.
func (e Elapsed) Duration() (time.Duration, bool) { return e.d, e.measured }

// IsMeasured reports whether a measurement was taken.
//
// It is not named Measured, because that is the constructor's name and a method
// sharing it would make `domain.Measured` and `e.Measured` two different things
// a reader has to keep apart.
func (e Elapsed) IsMeasured() bool { return e.measured }
