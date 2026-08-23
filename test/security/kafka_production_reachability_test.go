package security_test

import (
	gobuild "go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The module path every internal import is written against.
const modulePath = "github.com/hakanaltindag/svcdoctor"

// The package whose production reachability this file governs.
const kafkaAdapter = modulePath + "/internal/adapter/kafka"

// TestKafkaAdapterHasNoProductionImporter is the ADR 0054 gate for Kafka, and
// it is the reason Phase 6.1c-P1 was allowed to land an outcome that no rule
// yet owns.
//
// # What it protects
//
// internal/adapter/kafka can produce authentication outcomes with no diagnosis
// owner: EXEC_REQUIRED_INPUT_MISSING, EXEC_SKIPPED_BY_POLICY,
// AUTH_MECHANISM_UNSUPPORTED and AUTH_CREDENTIALS_REJECTED, beside FAIL
// outcomes on ApiVersions, SaslHandshake and Metadata. SummaryStatus is derived
// from findings alone, so any of those reaching a real report today would arrive
// as `status: OK` with `findings: []` — a wrong password rendered as a clean
// bill of health.
//
// ADR 0054 forbids shipping a FAIL-producing stage before something can explain
// it. The producer is nonetheless correct to exist: an outcome that is recorded
// but unowned is strictly better than one that was an invocation error and left
// no trace at all, and a rule cannot be written against evidence that no
// producer emits. What makes that safe is precisely this: **no production code
// path can reach the adapter**, so none of it can reach a report.
//
// # Why an import guard is the right shape
//
// Reachability here is not a routing question. `internal/app` composing Kafka
// would make every one of those outcomes production-reachable whether or not a
// CLI route existed, which is why "the Kafka CLI does not exist yet" was
// rejected as a justification when Phase 6.1c was stopped. An import edge is
// what actually creates the reach, so an import edge is what this asserts about.
//
// # When this test should change
//
// It should fail, loudly, on the first commit that composes Kafka into the
// application — and that commit is only correct if Phase 6.1c-P2 has already
// landed the diagnosis owners. Deleting or weakening this guard to make a
// composition commit pass is the exact failure ADR 0054 exists to prevent.
func TestKafkaAdapterHasNoProductionImporter(t *testing.T) {
	root := repositoryRoot(t)

	for _, dir := range productionPackages(t, root) {
		path := importPath(t, root, dir)
		// The adapter and its own wire package are what this governs, not what
		// it constrains.
		if strings.HasPrefix(path, kafkaAdapter) {
			continue
		}

		pkg, err := gobuild.ImportDir(dir, gobuild.ImportComment)
		if err != nil {
			// A directory with no buildable Go files is not a package.
			continue
		}
		// pkg.Imports covers production files only; test imports live in
		// TestImports and XTestImports and are deliberately not consulted. Tests
		// exercising the adapter are how it is verified at all.
		for _, imported := range pkg.Imports {
			if imported == kafkaAdapter {
				t.Errorf("%s imports %s in production code.\n\n"+
					"That makes every unowned Kafka outcome reachable from a real "+
					"report, including a rejected credential arriving as status OK "+
					"with no finding. ADR 0054 requires the diagnosis owners of "+
					"Phase 6.1c-P2 to land first.",
					path, kafkaAdapter)
			}
		}
	}
}

// TestNoKafkaCompositionEntryPointExists is the second half of the same gate.
//
// The import guard above catches a composition that is wired up. This catches
// one that is written but not yet called — a DiagnoseKafka sitting in
// internal/app awaiting a CLI route is already a composition root, and reviewing
// it as "unreachable" is how the ADR 0054 boundary erodes by one commit.
func TestNoKafkaCompositionEntryPointExists(t *testing.T) {
	root := repositoryRoot(t)

	for _, dir := range []string{"internal/app", "internal/cli", "cmd/svcdoctor"} {
		pkg, err := gobuild.ImportDir(filepath.Join(root, dir), 0)
		if err != nil {
			continue
		}
		for _, file := range pkg.GoFiles {
			path := filepath.Join(root, dir, file)
			source, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			if strings.Contains(string(source), "func DiagnoseKafka") {
				t.Errorf("%s declares DiagnoseKafka.\n\n"+
					"Kafka composition is blocked until Phase 6.1c-P2 gives the "+
					"protocol outcomes a diagnosis owner. See ADR 0054.", path)
			}
		}
	}
}

// repositoryRoot walks up from the test's directory to the module root.
func repositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test directory")
		}
		dir = parent
	}
}

// productionPackages returns every directory in the module that may hold
// production Go sources.
func productionPackages(t *testing.T, root string) []string {
	t.Helper()

	var dirs []string
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, tree),
			func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() && entry.Name() != "testdata" {
					dirs = append(dirs, path)
				}
				if entry.IsDir() && entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			})
		if err != nil {
			t.Fatalf("walking %s: %v", tree, err)
		}
	}
	if len(dirs) == 0 {
		t.Fatal("no package directories found; the guard would pass vacuously")
	}
	return dirs
}

// importPath maps a directory back to the import path it is reached by.
func importPath(t *testing.T, root, dir string) string {
	t.Helper()

	relative, err := filepath.Rel(root, dir)
	if err != nil {
		t.Fatalf("relating %s to %s: %v", dir, root, err)
	}
	return modulePath + "/" + filepath.ToSlash(relative)
}
