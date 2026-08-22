package cli

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// TestExitCodeMatrix pins docs/SCOPE.md's contract against real results.
//
// Every result here was produced by internal/app measuring a real socket, so the
// statuses are the ones the diagnosis layer actually derives rather than ones a
// test asserted into existence.
func TestExitCodeMatrix(t *testing.T) {
	tests := []struct {
		name       string
		result     func(*testing.T) app.Result
		err        error
		want       int
		wantStatus domain.SummaryStatus
		incomplete bool
	}{
		{
			name:       "complete run with nothing proven",
			result:     resultOKComplete,
			want:       ExitOK,
			wantStatus: domain.SummaryStatusOK,
		},
		{
			// The shape the whole phase turns on: findings exist, the report is
			// OK, and the exit code follows the summary rather than the finding
			// list. A mapping that counted findings would exit 1 here.
			name:       "complete run carrying only a warning",
			result:     resultWarnComplete,
			want:       ExitOK,
			wantStatus: domain.SummaryStatusOK,
		},
		{
			name:       "complete run with a target-side error",
			result:     resultProblemsComplete,
			want:       ExitProblemsFound,
			wantStatus: domain.SummaryStatusProblemsFound,
		},
		{
			name:       "local budget ended the run",
			result:     resultOKIncomplete,
			want:       ExitIncomplete,
			wantStatus: domain.SummaryStatusOK,
			incomplete: true,
		},
		{
			// The collision the whole contract turns on. docs/SCOPE.md: "A
			// partial run that found an ERROR still exits 4, and the findings
			// remain in the report." Getting this backwards would tell an
			// operator a truncated picture was the whole one.
			name:       "incomplete outranks a target-side error",
			result:     resultProblemsIncomplete,
			want:       ExitIncomplete,
			wantStatus: domain.SummaryStatusProblemsFound,
			incomplete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result(t)

			// The fixture has to be the shape the row claims, or the row proves
			// nothing about the mapping.
			if got := result.Report().Summary().Status(); got != tt.wantStatus {
				t.Fatalf("fixture status = %s, want %s", got, tt.wantStatus)
			}
			if tt.name == "complete run carrying only a warning" &&
				result.Report().FindingCount() == 0 {
				t.Fatal("the fixture carries no finding; the row proves nothing")
			}
			if result.Incomplete() != tt.incomplete {
				t.Fatalf("fixture Incomplete() = %v, want %v", result.Incomplete(), tt.incomplete)
			}

			if got := ExitCode(result, tt.err); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestExitCodeClassifiesErrors covers the two codes that carry no report.
func TestExitCodeClassifiesErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"a usage error", ErrUsage, ExitUsage},
		{"a wrapped usage error", usagef("--port %d is outside 1-65535", 0), ExitUsage},
		{"a deeply wrapped usage error", fmt.Errorf("parsing: %w", usagef("bad")), ExitUsage},
		{"the application rejecting its input", app.ErrInvalidInput, ExitUsage},
		{"a wrapped application input error", fmt.Errorf("x: %w", app.ErrInvalidInput), ExitUsage},
		{"anything else", errors.New("the graph could not be frozen"), ExitInternal},
		{"a cancelled context escaping as an error", context.Canceled, ExitInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(app.Result{}, tt.err); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestExitCodeIgnoresSeverityDirectly proves the mapping reads the report's own
// derived status and never re-counts findings.
//
// A report can carry findings and still be OK — the WARN case ADR 0046 created —
// and the exit code must follow the summary, not the finding list.
func TestExitCodeIgnoresSeverityDirectly(t *testing.T) {
	result := resultProblemsComplete(t)
	report := result.Report()

	if report.FindingCount() == 0 {
		t.Fatal("the fixture has no findings; this test proves nothing")
	}
	counts := report.Summary().FindingCountsBySeverity()
	if counts.Error == 0 {
		t.Fatalf("the fixture has no ERROR finding: %+v", counts)
	}
	// Status is what the mapping reads, and it already encodes the severity
	// question exactly once.
	if got := ExitCode(result, nil); got != ExitProblemsFound {
		t.Errorf("ExitCode = %d, want %d", got, ExitProblemsFound)
	}
}
