// Package harness asserts what one svcdoctor run is allowed to claim.
//
// # What it is
//
// A scenario arranges ground truth, runs svcdoctor, and hands the frozen
// outcome here as a [Subject] together with an [Expectation]. The harness
// checks the expectation and reports what did not hold.
//
// # What it is not
//
// It is not a test platform, and it knows no service. It contains no branch on
// PostgreSQL, Kafka or Redis, imports no adapter, wire or diagnosis package, and
// holds no protocol knowledge. Everything service-shaped — which step names
// exist, which finding codes a rule can produce, how to break a network path,
// how to count an AUTH on the wire — is the scenario's, and stays in the
// service's own integration package.
//
// The division is the point. `test/integration/postgres` knows `pg_hba.conf`;
// this package knows that a node has a state and a finding has a code. If a
// change here ever needs to know which service it is looking at, the
// abstraction was wrong and should be removed rather than branched.
//
// # Why the expectation is a struct and not a scenario name
//
// `harness.Assert(t, subject, harness.Expectation{...})` keeps the contract at
// the call site, so a reviewer reads one test and sees what happened, what
// svcdoctor may claim, and what it must not claim. A registry keyed by scenario
// name would move all three somewhere else, which is the opposite of what this
// repository's evidence discipline needs.
package harness

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// T is the part of *testing.T the harness uses.
//
// It is an interface for one reason: `testing.TB` carries an unexported method
// and cannot be implemented outside the standard library, so without this the
// harness's own tests could not observe what an assertion reported. A failing
// subtest fails its parent, which makes "prove this rejects a bad subject"
// unwritable through `t.Run`.
//
// *testing.T satisfies it, so every call site is still `harness.Assert(t, ...)`.
type T interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Subject is the frozen outcome of one run, in the only vocabulary the harness
// understands.
//
// Services carry their results differently — one holds an app.Result, another a
// report and graph assembled by a lower-level pass — so the scenario adapts to
// this rather than the harness adapting to three shapes.
type Subject struct {
	// Name identifies the scenario in failure messages.
	Name string

	// Report is the canonical report the run produced.
	Report domain.Report

	// Incomplete is Result.Incomplete(), supplied by the scenario because not
	// every carrier in the repository exposes it.
	Incomplete bool

	// Shareable is the redacted report, when the scenario produced one. A
	// secret assertion covers it in addition to Report when it is set.
	Shareable *domain.Report

	// Text is an optional rendered surface — terminal output, JSON — that the
	// prose rules apply to in addition to the findings' own wording.
	Text string

	// CredentialAttempts is how many credential-bearing exchanges the scenario
	// observed. Nil means the scenario did not measure it.
	//
	// **The scenario counts; the harness only bounds.** Counting is
	// service-specific — a broker's own metrics, an ACL log, a recording peer —
	// and no counter was added to production code to make this convenient.
	CredentialAttempts *int
}

// Expectation is what the scenario says the run is allowed to have produced.
//
// A nil pointer field means "not asserted". An empty slice means the same. That
// keeps a scenario's call site to the facts it actually pins.
type Expectation struct {
	// --- result ---

	Summary          *domain.SummaryStatus
	FirstBrokenLayer *domain.Layer
	Incomplete       *bool

	// --- findings ---

	RequireFindings []domain.FindingCode
	ForbidFindings  []domain.FindingCode
	FindingCount    *int

	// --- graph ---

	Nodes       []Node
	AbsentSteps []domain.Step
	NodeCounts  map[domain.Step]int
	Edges       []Edge

	// --- claim discipline ---

	// RequireProse and ForbidProse match case-insensitively against every
	// finding's summary, detail and recommendations.
	RequireProse []string
	ForbidProse  []string

	// --- security ---

	ForbidSecrets         []string
	MaxCredentialAttempts *int
}

// Node is one expected evidence node, identified by its step.
//
// State and failure class are always both stated. A step's state without its
// class is half an answer — PASS/NONE and UNKNOWN/EXEC_LOCAL_TIMEOUT are
// different claims about the same step — and every scenario migrated here
// already knew both.
type Node struct {
	Step         domain.Step
	State        domain.State
	FailureClass domain.FailureClass
}

// Edge is an expected parent relationship between two steps.
type Edge struct{ Parent, Child domain.Step }

// Assert checks every stated expectation and reports each one that did not hold.
//
// It reports all failures rather than stopping at the first, because a scenario
// that broke usually broke in more than one way and one run of the fixture is
// expensive. It stops only where continuing would be meaningless.
func Assert(t T, s Subject, e Expectation) {
	t.Helper()

	if s.Report.IsZero() {
		t.Fatalf("%s: the scenario produced no report", s.label())
	}

	assertResult(t, s, e)
	assertFindings(t, s, e)
	assertGraph(t, s, e)
	assertProse(t, s, e)
	assertSecurity(t, s, e)
}

func assertResult(t T, s Subject, e Expectation) {
	t.Helper()

	if e.Summary != nil {
		if got := s.Report.Summary().Status(); got != *e.Summary {
			t.Errorf("%s: summary status = %s, want %s", s.label(), got, *e.Summary)
		}
	}
	if e.FirstBrokenLayer != nil {
		if got := s.Report.Summary().FirstBrokenLayer(); got != *e.FirstBrokenLayer {
			t.Errorf("%s: first broken layer = %s, want %s",
				s.label(), got, *e.FirstBrokenLayer)
		}
	}
	if e.Incomplete != nil {
		if s.Incomplete != *e.Incomplete {
			t.Errorf("%s: Incomplete() = %t, want %t.\n\n"+
				"Incompleteness is svcdoctor's own execution budget and is orthogonal "+
				"to the summary status; UNKNOWN is not FAIL.",
				s.label(), s.Incomplete, *e.Incomplete)
		}
	}
}

func (s Subject) label() string {
	if s.Name == "" {
		return "scenario"
	}
	return s.Name
}

// --- small constructors, so a call site reads as a sentence ------------------

// Status returns a pointer to a summary status.
func Status(v domain.SummaryStatus) *domain.SummaryStatus { return &v }

// BrokenAt returns a pointer to a layer.
func BrokenAt(v domain.Layer) *domain.Layer { return &v }

// Incomplete returns a pointer to true.
func Incomplete() *bool { v := true; return &v }

// Complete returns a pointer to false.
func Complete() *bool { v := false; return &v }

// Count returns a pointer to n.
func Count(n int) *int { return &n }
