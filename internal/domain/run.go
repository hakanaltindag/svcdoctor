package domain

import (
	"fmt"
	"time"
)

// RunMetadata records the execution facts of one diagnostic run.
//
// Every value is supplied by the caller. This type performs no discovery: it
// does not read a clock, inspect arguments or the environment, or work out which
// version of svcdoctor is running. Orchestration knows those things; this is
// where the answers are kept.
//
// # Why there is no execution mode
//
// docs/REPORT_SCHEMA.md section 2 lists an execution mode among the run
// concepts, and it is deliberately absent.
//
// No document defines its vocabulary, and the two things it could plausibly mean
// already have owners. Where a run executed from is Vantage, which ADR 0012
// makes a first-class report section precisely so it is not buried in run
// metadata. Whether a run completed fully is incompleteness, which
// docs/ARCHITECTURE.md section 13 assigns to the summary and the exit code.
// Adding a third field would either duplicate one of them or invent semantics
// nothing consumes.
//
// It can be added when a real execution mode exists and means something neither
// of those already says.
//
// The zero RunMetadata is invalid. Use NewRunMetadata.
type RunMetadata struct {
	svcdoctorVersion string
	startedAt        time.Time
	duration         time.Duration
	service          ServiceID
}

// NewRunMetadata records the execution facts of a run.
//
// startedAt is normalized to UTC, matching TimeAttr and Evidence, so an instant
// encodes identically wherever it was produced.
func NewRunMetadata(
	svcdoctorVersion string, startedAt time.Time, duration time.Duration, service ServiceID,
) (RunMetadata, error) {
	if err := validateIdentifier("svcdoctor version", svcdoctorVersion); err != nil {
		return RunMetadata{}, err
	}
	if startedAt.IsZero() {
		return RunMetadata{}, fmt.Errorf("%w: run requires a start time", ErrInvalidValue)
	}
	if duration < 0 {
		return RunMetadata{}, fmt.Errorf(
			"%w: run duration %s must not be negative", ErrInvalidValue, duration)
	}
	if !service.Valid() {
		return RunMetadata{}, fmt.Errorf("%w: service id %q", ErrInvalidValue, service)
	}
	return RunMetadata{
		svcdoctorVersion: svcdoctorVersion,
		startedAt:        startedAt.UTC(),
		duration:         duration,
		service:          service,
	}, nil
}

// SvcdoctorVersion returns the version that produced the report.
func (r RunMetadata) SvcdoctorVersion() string { return r.svcdoctorVersion }

// StartedAt returns when the run began, in UTC.
func (r RunMetadata) StartedAt() time.Time { return r.startedAt }

// Duration returns how long the run took.
func (r RunMetadata) Duration() time.Duration { return r.duration }

// Service returns which service was inspected.
func (r RunMetadata) Service() ServiceID { return r.service }

// IsZero reports whether r is the invalid zero RunMetadata.
func (r RunMetadata) IsZero() bool { return r == RunMetadata{} }

// RunMetadata deliberately implements no MarshalJSON. The report encodes the run
// section itself, because docs/REPORT_SCHEMA.md section 2 has it repeat two
// facts that this type does not own: whether TLS verification was disabled and
// which output mode was produced. Those live once in ReportSecurity, and the
// report writes them into both sections so the two cannot disagree.
