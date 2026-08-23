package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// The Result axis, and the documents that describe it.
//
// # Why a doc audit lives beside a command test
//
// Phase 6.4 renamed the Result block's label from `session` to `outcome`
// (ADR 0052 §2) in output that v0.1.0 already shipped. The renderer's own tests
// pin the new wording, and nothing pinned the two places an operator meets it
// *outside* the renderer: the README's worked examples, and the help text's
// warning that exit 0 is not success.
//
// Both drift silently. A README example showing a label the product no longer
// emits is a support ticket, and a help text that quietly loses its warning
// turns exit 0 into the success signal ADR 0048 §9 spent a section saying it is
// not. Neither is caught by any test that reads Go code, so these read the
// artifacts.

// TestTheResultAxisIsOutcomeForBothServices pins the label at the command
// boundary.
//
// The renderer decides it, but this is where a regression would reach a person:
// two services, one axis, and neither may reintroduce a service-specific label.
func TestTheResultAxisIsOutcomeForBothServices(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "postgres",
			args: []string{"diagnose", "postgres", "--host", "db", "--user", "app"},
			want: "outcome session established",
		},
		{
			name: "kafka",
			args: []string{"diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN"},
			want: "outcome session established",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The same PostgreSQL result through both commands. The axis is the
			// renderer's, derived from the report's own service, so this shows
			// the *label* is service-neutral without asserting that a Kafka
			// command can produce a PostgreSQL value.
			h := newHarness(resultOKComplete(t), nil)
			h.run(tt.args...)

			if !hasRow(h.stdout.String(), tt.want) {
				t.Errorf("no Result row %q:\n%s", tt.want, h.stdout.String())
			}
			if strings.Contains(h.stdout.String(), "\n  session") {
				t.Errorf("the Result block reintroduced a `session` label:\n%s", h.stdout.String())
			}
		})
	}
}

// TestThePostgresValueWordingIsUnchanged is the other half of ADR 0052 §2.
//
// The label generalized; the value did not. "established" alone, or any reword,
// would be a change the record did not authorize.
func TestThePostgresValueWordingIsUnchanged(t *testing.T) {
	established := newHarness(resultOKComplete(t), nil)
	established.run("diagnose", "postgres", "--host", "db", "--user", "app")
	if !hasRow(established.stdout.String(), "outcome session established") {
		t.Errorf("a run that reached a session does not say so:\n%s", established.stdout.String())
	}

	// The load-bearing case: the endpoint demanded authentication, the run had
	// none, the status is OK and there is **no session**. The value must say so
	// in as many words, on an OK report, at exit 0.
	none := newHarness(resultWarnComplete(t), nil)
	code := none.run("diagnose", "postgres", "--host", "db", "--user", "app")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	out := none.stdout.String()
	if !hasRow(out, "outcome session NOT established") {
		t.Errorf("a run with no session does not say so:\n%s", out)
	}
	if !hasRow(out, "status OK no target-side error was proven") {
		t.Errorf("the OK gloss is missing:\n%s", out)
	}
}

// TestTheHelpStillWarnsThatExitZeroIsNotSuccess pins the sentence the
// terminology change must not have weakened.
func TestTheHelpStillWarnsThatExitZeroIsNotSuccess(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"diagnose", "postgres", "--help"},
			"Exit code 0 does not mean a session was established."},
		{[]string{"diagnose", "kafka", "--help"},
			"Exit code 0 does not mean Kafka metadata was obtained."},
	}

	for _, tt := range tests {
		h := newHarness(app.Result{}, nil)
		if code := h.run(tt.args...); code != ExitOK {
			t.Fatalf("`%s` exit = %d", strings.Join(tt.args, " "), code)
		}
		if !strings.Contains(h.stdout.String(), tt.want) {
			t.Errorf("`%s` help lost the warning %q", strings.Join(tt.args, " "), tt.want)
		}
	}
}

// TestTheREADMEResultExamplesMatchTheProduct reads the shipped document.
//
// It checks the label and the value wording rather than whole blocks: the
// README's durations are illustrative and its hostnames are not this test's
// fixtures, so pinning entire examples would fail on prose edits that change
// nothing an operator would notice.
func TestTheREADMEResultExamplesMatchTheProduct(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	// No example may show the label the product stopped emitting. Anchored to
	// the start of a Result row, so prose that discusses a session is untouched.
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "  session ") || strings.HasPrefix(line, "  session\t") {
			t.Errorf("a README example still shows the old Result label:\n%s", line)
		}
	}

	// And the examples that exist show the wording the product emits. Padding is
	// collapsed: a Result column's width is set by the widest cell in its own
	// block, so the same row is spaced differently in an example that carries a
	// `first break` line and one that does not.
	for _, want := range []string{
		"outcome session established",
		"outcome session NOT established",
		"outcome Kafka metadata obtained",
	} {
		if !hasRow(readme, want) {
			t.Errorf("the README has no example showing %q", want)
		}
	}
}

// hasRow reports whether one Result row is present, ignoring the column padding
// tabwriter chose for that document.
func hasRow(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.Join(strings.Fields(line), " ") == want {
			return true
		}
	}
	return false
}

// readRepoFile reads a file from the repository root, which is two directories
// up from internal/cli.
func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", name)
	contents, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: a fixed repository path.
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(contents)
}
