package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 9.2B, ADR 0075 §2.6: the seven help surfaces have golden snapshots.
//
// # Why
//
// Help text is the document most operators read and the one least often
// reviewed. Phase 9.2A found `diagnose redis` missing the exit-code block every
// sibling carried, and `run` — the command written for CI — missing it too.
// Neither was a decision; both were drift, and nothing in the build could see
// either, because a help string is a string.
//
// A golden file does not make help text correct. It makes a change to it
// **visible**: an intentional edit is a reviewed diff, and an accidental one is
// a failing test.
//
// Update with:
//
//	go test ./internal/cli -run TestUX0102030TheHelpSurfacesMatchTheirGoldens -update
//
// and read the diff before committing it.

// updateHelpGoldens reuses golden_test.go's -update flag rather than declaring a
// second one: two flag.Bool("update", …) in one test binary is a panic at init,
// and one switch for every golden in the package is what a reader expects.
func updateHelpGoldens() bool { return *update }

// helpSurfaces is every way an operator can ask svcdoctor what it does.
//
// Seven, and the list is asserted complete: a sixth command whose help nobody
// snapshotted is exactly the drift this exists to catch.
var helpSurfaces = []struct {
	name string
	args []string
}{
	{"root", []string{"--help"}},
	{"diagnose", []string{"diagnose", "--help"}},
	{"postgres", []string{"diagnose", "postgres", "--help"}},
	{"kafka", []string{"diagnose", "kafka", "--help"}},
	{"redis", []string{"diagnose", "redis", "--help"}},
	{"rabbitmq", []string{"diagnose", "rabbitmq", "--help"}},
	{"run", []string{"run", "--help"}},
}

func TestUX0102030TheHelpSurfacesMatchTheirGoldens(t *testing.T) {
	for _, surface := range helpSurfaces {
		t.Run(surface.name, func(t *testing.T) {
			got := runCLI(t, context.Background(), surface.args...)

			if got.code != ExitOK {
				t.Fatalf("`svcdoctor %s` exited %d; asking for help is not an error",
					strings.Join(surface.args, " "), got.code)
			}
			if got.stderr != "" {
				t.Errorf("help was written to stderr.\n\n"+
					"Help is the answer to the question that was asked, so it belongs on "+
					"stdout where it can be piped, paged and grepped.\nstderr: %s", got.stderr)
			}

			path := filepath.Join("testdata", "help", surface.name+".txt")
			if updateHelpGoldens() {
				if err := os.WriteFile(path, []byte(got.stdout), 0o600); err != nil {
					t.Fatalf("writing %s: %v", path, err)
				}
				return
			}

			want, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("reading %s: %v\n\nRun with -update to create it.", path, err)
			}
			if got.stdout != string(want) {
				t.Errorf("`svcdoctor %s` no longer matches %s.\n\n"+
					"If the change is intentional, re-run with -update and review the diff. "+
					"If it is not, this is the accidental public-surface change the golden "+
					"exists to catch.\n\ngot:\n%s\nwant:\n%s",
					strings.Join(surface.args, " "), path, got.stdout, string(want))
			}
		})
	}
}

// TestUX02EveryHelpSurfaceCarriesItsContract is the part a golden cannot check.
//
// A golden pins what the text *is*. It cannot say whether the text is complete,
// because a snapshot of an incomplete help page is a perfectly stable snapshot —
// which is precisely how `diagnose redis` kept no exit-code block through three
// phases.
//
// So this asserts the elements ADR 0075 §2.3 requires, per surface, by what they
// have to communicate rather than by their exact words.
func TestUX02EveryHelpSurfaceCarriesItsContract(t *testing.T) {
	leaves := []string{"postgres", "kafka", "redis", "rabbitmq"}

	for _, service := range leaves {
		t.Run(service, func(t *testing.T) {
			help := helpOf(t, "diagnose", service, "--help")

			// The exit-code block. All five codes, on every leaf.
			for _, code := range []string{"  0", "  1", "  2", "  3", "  4"} {
				if !strings.Contains(help, code) {
					t.Errorf("no exit code %s is documented", strings.TrimSpace(code))
				}
			}
			if !strings.Contains(help, "Exit code") && !strings.Contains(help, "Exit codes") {
				t.Error("there is no exit-code section")
			}

			// The caveat. Exit 0 is the code most likely to be misread as
			// "the service works", and every leaf has to say it does not.
			if !strings.Contains(help, "Exit code 0 does not mean") {
				t.Error("the help does not warn that exit 0 is not success.\n\n" +
					"It is the single most misread thing svcdoctor produces: a run that " +
					"withheld its credential over a plaintext channel exits 0 having " +
					"established nothing.")
			}

			// Credential safety, TLS and output selection.
			for _, want := range []struct{ needle, why string }{
				{"--password-file", "the credential sources"},
				{"--tls", "the transport-encryption flags"},
				{"--output", "the output selection"},
				{"--shareable", "the shareable projection"},
			} {
				if !strings.Contains(help, want.needle) {
					t.Errorf("the help does not document %s", want.why)
				}
			}

			// Usage, and a one-sentence purpose above it.
			usage := strings.Index(help, "Usage:")
			if usage <= 0 {
				t.Fatal("the help has no Usage section, or nothing above it")
			}
			if len(strings.TrimSpace(help[:usage])) < 40 {
				t.Error("there is no one-sentence purpose above the usage line")
			}
		})
	}

	t.Run("run", func(t *testing.T) {
		help := helpOf(t, "run", "--help")

		if !strings.Contains(help, "Exit codes:") {
			t.Error("`run --help` documents no exit codes.\n\n" +
				"It is the command written for CI, so it is the one that most needs them.")
		}
		if !strings.Contains(help, "Exit code 0 does not mean") {
			t.Error("`run --help` does not warn that exit 0 is not success")
		}
		for _, want := range []string{"--config", "--timeout", "--concurrency", "--output", "--shareable"} {
			if !strings.Contains(help, want) {
				t.Errorf("`run --help` does not document %s", want)
			}
		}
		// The credential model, because `run` is where it differs.
		if !strings.Contains(help, "env: NAME") || !strings.Contains(help, "file: PATH") {
			t.Error("`run --help` does not show how a target names a credential")
		}
	})

	t.Run("root", func(t *testing.T) {
		help := helpOf(t, "--help")

		for _, want := range []string{"diagnose", "run", "--version", "--help"} {
			if !strings.Contains(help, want) {
				t.Errorf("root help does not mention %q", want)
			}
		}
		// ADR 0075 §2.2: the mental model, on the surface an operator reaches
		// first. Without it, `diagnose` and `run` read as unrelated systems.
		lower := strings.ToLower(strings.Join(strings.Fields(help), " "))
		if !strings.Contains(lower, "one service") && !strings.Contains(lower, "one endpoint") {
			t.Error("root help does not say that `diagnose` measures one endpoint")
		}
		if !strings.Contains(lower, "configuration file") {
			t.Error("root help does not say that `run` measures the targets in a file")
		}
	})
}

// TestUX01TheHelpGoldensCoverEveryCommand keeps the snapshot list complete.
//
// A command added without a golden is a public surface nobody reviews. This
// reads the root and `diagnose` help for the names they advertise and requires a
// snapshot for each, so the list above cannot fall behind the product.
func TestUX01TheHelpGoldensCoverEveryCommand(t *testing.T) {
	snapshotted := map[string]bool{}
	for _, surface := range helpSurfaces {
		snapshotted[surface.name] = true
	}

	root := helpOf(t, "--help")
	for _, command := range []string{"diagnose", "run"} {
		if !strings.Contains(root, command) {
			t.Fatalf("root help does not advertise %q; this guard reads it to find the "+
				"commands, so it would pass vacuously", command)
		}
		if !snapshotted[command] {
			t.Errorf("`%s` is advertised in root help and has no golden", command)
		}
	}

	diagnose := helpOf(t, "diagnose", "--help")
	var found int
	for _, service := range []string{"postgres", "kafka", "redis", "rabbitmq"} {
		if !strings.Contains(diagnose, service) {
			continue
		}
		found++
		if !snapshotted[service] {
			t.Errorf("`diagnose %s` is advertised and has no golden", service)
		}
	}
	if found != 4 {
		t.Errorf("`diagnose --help` advertises %d of the 4 known services; either a "+
			"service was removed, or this list is stale", found)
	}
	if !snapshotted["root"] {
		t.Error("root help itself has no golden")
	}
}

// helpOf runs one help surface and returns its stdout.
//
// Distinct from docsclaims_test.go's helpText, which takes a service name: these
// surfaces include the root and `run`, which are not services.
func helpOf(t *testing.T, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	if code := newTestApp(&stdout, &stderr).Run(context.Background(), args); code != ExitOK {
		t.Fatalf("`svcdoctor %s` exited %d: %s", strings.Join(args, " "), code, stderr.String())
	}
	return stdout.String()
}
