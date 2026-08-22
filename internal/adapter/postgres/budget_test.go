package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The local-timeout guard, for every classifier in this package.
//
// Phase 4.11c found the same defect in two of the four: a step's own deadline is
// applied to the socket by wire.bindDeadline, so it comes back as a net.Error
// timeout and never as context.DeadlineExceeded. A classifier that checks only
// the caller's context therefore falls through to its wire branch, and
// svcdoctor's budget is published as the endpoint's protocol failure.
//
// This table exists so that a classifier added or rewritten later has to be
// listed here, and so that removing a guard fails a named test rather than
// quietly re-creating the defect. os.ErrDeadlineExceeded is exactly what a
// socket read deadline returns.

// timeoutErr is what a socket whose deadline expired reports.
var timeoutErr = os.ErrDeadlineExceeded

func TestEveryClassifierCallsALocalDeadlineItsOwn(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		state   domain.State
		failure domain.FailureClass
	}{
		{
			name: "ssl_request",
			state: func() domain.State {
				s, _, _ := classifySSLResponse(ctx, wire.SSLResponse(0), timeoutErr)
				return s
			}(),
			failure: func() domain.FailureClass {
				_, f, _ := classifySSLResponse(ctx, wire.SSLResponse(0), timeoutErr)
				return f
			}(),
		},
		{
			name: "startup",
			state: func() domain.State {
				s, _ := classifyStartup(ctx, wire.AuthRequest{}, wire.ErrorFields{}, timeoutErr)
				return s
			}(),
			failure: func() domain.FailureClass {
				_, f := classifyStartup(ctx, wire.AuthRequest{}, wire.ErrorFields{}, timeoutErr)
				return f
			}(),
		},
		{
			name: "authentication",
			state: func() domain.State {
				s, _ := authObservation{err: timeoutErr}.classify()
				return s
			}(),
			failure: func() domain.FailureClass {
				_, f := authObservation{err: timeoutErr}.classify()
				return f
			}(),
		},
		{
			name: "session",
			state: func() domain.State {
				s, _ := sessionObservation{err: timeoutErr}.classify()
				return s
			}(),
			failure: func() domain.FailureClass {
				_, f := sessionObservation{err: timeoutErr}.classify()
				return f
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.state != domain.StateUnknown {
				t.Errorf("state = %s, want UNKNOWN; a deadline svcdoctor set is not "+
					"a positively evidenced failure of the endpoint", tt.state)
			}
			if tt.failure != domain.FailureExecLocalTimeout {
				t.Errorf("class = %s, want EXEC_LOCAL_TIMEOUT", tt.failure)
			}
		})
	}
}

// TestAPeerFactStillOutranksTheDeadline is the other half. The guard added above
// sits *after* every branch that reads what the peer actually said, so an answer
// that arrived is still the answer even when the step later timed out. Without
// this, the fix would have turned real protocol failures into local timeouts.
func TestAPeerFactStillOutranksTheDeadline(t *testing.T) {
	ctx := context.Background()

	t.Run("ssl_request completed exchange", func(t *testing.T) {
		// A real answer arrives with a nil error and decides on its own.
		state, _, offered := classifySSLResponse(ctx, wire.SSLDeclined, nil)
		if state != domain.StateFail || offered {
			t.Errorf("declined = %s/offered=%v, want FAIL/false", state, offered)
		}
	})

	t.Run("startup error response", func(t *testing.T) {
		// An ErrorResponse read before the deadline still names the target fact.
		state, failure := classifyStartup(
			ctx, wire.AuthRequest{}, wire.ErrorFields{SQLState: "28000"}, timeoutErr)
		if state != domain.StateFail {
			t.Errorf("state = %s, want FAIL; the peer answered", state)
		}
		if failure == domain.FailureExecLocalTimeout {
			t.Error("a peer's own SQLSTATE was reclassified as svcdoctor's timeout")
		}
	})

	t.Run("session error response", func(t *testing.T) {
		state, failure := sessionObservation{
			fields: wire.ErrorFields{SQLState: "3D000"}, err: timeoutErr,
		}.classify()
		if state != domain.StateFail || failure == domain.FailureExecLocalTimeout {
			t.Errorf("= %s/%s; a peer's SQLSTATE outranks a later deadline",
				state, failure)
		}
	})
}

// TestStartupParamsCarryABudget pins the field whose absence was the defect. A
// step that cannot be told a budget cannot honour one, and every sibling in this
// package takes the same value from internal/app.
func TestStartupParamsCarryABudget(t *testing.T) {
	if err := (StartupParams{User: "u", ExchangeTimeout: -1}).validate(); err == nil {
		t.Error("a negative exchange timeout was accepted")
	}
	if err := (StartupParams{User: "u"}).validate(); err != nil {
		t.Errorf("a zero exchange timeout was rejected: %v; zero means the "+
			"caller's context is the only bound", err)
	}
}
