//go:build integration

package postgres

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Guards over the boundary this phase is most likely to erode.
//
// Phase 4.8a composes production stages from a test. The danger is not that the
// harness is wrong — its tests would catch that — but that it quietly becomes
// the architecture: a `[0]` here, a production runner there, and the decisions
// ADR 0041 exists to make get made by accident instead.

// repoRoot walks up to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving the working directory: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// productionGoFiles returns every non-test .go file under internal/ and cmd/.
func productionGoFiles(t *testing.T) []string {
	t.Helper()

	root := repoRoot(t)
	var out []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			out = append(out, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", top, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no production sources found")
	}
	return out
}

func parseFile(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return f
}

// TestTheProductBoundaryExists is the positive form of a guard that used to
// assert emptiness.
//
// Until Phase 5.1 this file asserted that `cmd/svcdoctor` and `internal/render`
// held no Go code, because the product boundary was undecided and an accidental
// renderer would have made decisions ADR 0048 had not yet made. ADR 0048 made
// them and Phase 5.1 built the spine, so asserting emptiness would now assert
// the opposite of the decision — which is exactly the failure mode that guard
// existed to prevent, pointed the other way.
//
// What replaces it is the set of properties that were actually load-bearing.
func TestTheProductBoundaryExists(t *testing.T) {
	root := repoRoot(t)

	for _, dir := range []string{
		filepath.Join(root, "cmd", "svcdoctor"),
		filepath.Join(root, "internal", "cli"),
		filepath.Join(root, "internal", "render", "json"),
		filepath.Join(root, "internal", "platform", "local"),
	} {
		if len(goFilesIn(t, dir)) == 0 {
			t.Errorf("%s holds no Go code; Phase 5.1 builds the CLI spine there", dir)
		}
	}
}

// TestTheCLIReachesOnlyTheApplication pins what the command boundary may know.
//
// The CLI is a composition layer, so it names concrete things on purpose: the
// system resolver and dialer, the PostgreSQL TLS plan, the local vantage
// producer. **What it must never import is internal/diagnosis.** Rules run
// inside the application over frozen evidence, and a command that could call one
// could publish a finding nobody measured.
//
// It must also not reach a wire package, where the protocol and the one
// authorized security.Reveal live.
func TestTheCLIReachesOnlyTheApplication(t *testing.T) {
	// internal/security and internal/security/redaction became authorized CLI
	// imports in Phase 5.2: the command constructs the credential (ADR 0049) and
	// owns the output-security choice (ADR 0048 §6). What stays forbidden is
	// anything that would let it conclude something.
	forbidden := []string{
		"internal/diagnosis",
		"internal/adapter/postgres/wire",
		"internal/adapter/kafka",
	}
	for path, imports := range importsUnder(t, filepath.Join(repoRoot(t), "internal", "cli")) {
		for _, imported := range imports {
			for _, deny := range forbidden {
				if strings.Contains(imported, deny) {
					t.Errorf("%s imports %s; the command boundary may not reach it",
						path, imported)
				}
			}
		}
	}
}

// TestTheRendererIsPresentationOnly is ADR 0048 section 3, enforced.
//
// A renderer that could import the application would start deciding exit codes;
// one that could import diagnosis would start producing findings; one that could
// import redaction could emit shareable-looking bytes whose own security
// metadata disagreed. depguard carries the same rule, and this test states it in
// the repository's own terms so that a weakened lint config is visible here too.
func TestTheRendererIsPresentationOnly(t *testing.T) {
	forbidden := []string{
		"internal/app",
		"internal/adapter",
		"internal/probe",
		"internal/diagnosis",
		"internal/security",
		"internal/platform",
		"internal/cli",
		"net/http",
		"os/exec",
	}
	for path, imports := range importsUnder(t, filepath.Join(repoRoot(t), "internal", "render")) {
		for _, imported := range imports {
			for _, deny := range forbidden {
				if strings.Contains(imported, deny) {
					t.Errorf("%s imports %s; a renderer presents and nothing else",
						path, imported)
				}
			}
		}
	}
}

// TestTheRendererInterpretsNothing pins what presentation may not become.
//
// A renderer that summed stage durations would publish a total the run never
// measured; one that read SummaryStatus to decide whether a session happened
// would call a no-credential run successful; one that graded a duration would
// invent the latency diagnosis PostgreSQL BASIC is frozen without. Each is a
// single line away, so each is checked in the source rather than left to review.
func TestTheRendererInterpretsNothing(t *testing.T) {
	root := filepath.Join(repoRoot(t), "internal", "render")

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		code := codeWithoutComments(t, path)

		for _, forbidden := range []string{
			// The total comes from the run's own metadata, never a sum.
			"+= node.Duration", "+= n.Duration", "total +=", "sum +=",
			// Session establishment is a passing session node, nothing else.
			"SummaryStatusOK &&", "FindingCount() == 0 &&",
			// No performance vocabulary anywhere in the decisions.
			"\"slow\"", "\"fast\"", "\"degraded\"", "threshold",
			// No identifiers parsed, no environment, no terminal.
			"strings.Split(string(", "os.Getenv", "os.Stdin", "isatty", "Isatty",
			// No escape sequences.
			"\\x1b", "\\033",
		} {
			if strings.Contains(code, forbidden) {
				t.Errorf("%s references %q; a renderer presents and interprets nothing",
					path, forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
}

// TestTheTotalDurationIsRunMetadata is the Phase 4.11c-R2 closure invariant,
// enforced where a renderer would break it.
func TestTheTotalDurationIsRunMetadata(t *testing.T) {
	path := filepath.Join(repoRoot(t), "internal", "render", "terminal", "report.go")
	code := codeWithoutComments(t, path)

	if !strings.Contains(code, "Run().Duration()") {
		t.Error("the terminal renderer does not take its total from the run metadata")
	}
}

// TestTheCredentialSurfaceIsExactlyTwoFlags replaces the Phase 5.1 guard that
// asserted no credential surface existed at all.
//
// Phase 5.2 added one, so asserting its absence would now assert the opposite of
// ADR 0049. What survives is the part that was actually load-bearing: exactly
// two sources, both explicit, and none of the three the ADR refuses or defers.
//
// # It is a set, not a list, and Phase 6.4C is why
//
// `diagnose kafka` declares the same two flags as `diagnose postgres`, because
// each service owns its own flag set (ADR 0041) and both read a credential the
// same way. That is two declarations of each name, not four names. The assertion
// is over the distinct **names**, so a third source — an environment variable, a
// literal `--password`, a DSN — still fails on either command, while a third
// service reusing the two allowed ones does not.
func TestTheCredentialSurfaceIsExactlyTwoFlags(t *testing.T) {
	root := filepath.Join(repoRoot(t), "internal", "cli")

	var flags []string
	for _, path := range goFilesIn(t, root) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		code := codeWithoutComments(t, path)

		// The declared flag names, read from the fs.X("name", ...) calls.
		for _, m := range regexp.MustCompile(`fs\.\w+\("([a-z-]+)"`).FindAllStringSubmatch(code, -1) {
			if strings.Contains(m[1], "password") && !slices.Contains(flags, m[1]) {
				flags = append(flags, m[1])
			}
		}

		// No environment source, no prompt, and no reach around the injected
		// input. os.Stdin belongs to cmd/svcdoctor, which passes it in.
		for _, forbidden := range []string{
			"os.Getenv", "os.LookupEnv", "os.Environ", "os.Stdin", "Reveal", "SecretFor",
		} {
			if strings.Contains(code, forbidden) {
				t.Errorf("%s references %q; the credential arrives only through the two "+
					"declared flags, and the CLI never opens a Secret", path, forbidden)
			}
		}
	}

	sort.Strings(flags)
	want := []string{"password-file", "password-stdin"}
	if !slices.Equal(flags, want) {
		t.Errorf("credential flags = %v, want %v; a literal --password is refused "+
			"outright by ADR 0049 and further sources are deferred", flags, want)
	}
}

// codeWithoutComments returns a file's code with every comment removed, so a
// guard can forbid an implementation without forbidding the sentence that
// explains why the implementation is shaped as it is.
func codeWithoutComments(t *testing.T, path string) string {
	t.Helper()

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	var out strings.Builder
	if err := printer.Fprint(&out, fset, parsed); err != nil {
		t.Fatalf("printing %s: %v", path, err)
	}
	return out.String()
}

// goFilesIn lists the Go files directly in a directory.
func goFilesIn(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// importsUnder maps every Go file under root to the packages it imports.
func importsUnder(t *testing.T, root string) map[string][]string {
	t.Helper()

	out := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range parsed.Imports {
			out[path] = append(out[path], strings.Trim(spec.Path.Value, `"`))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

// TestTheCompositionRootKeepsItsServicesInSeparateFiles is what the
// PostgreSQL-only guard became when Kafka composition landed.
//
// # Why the original assertion is gone, and what replaced it
//
// It asserted that no file in `internal/app` imports `adapter/kafka` or
// `diagnosis/kafka`, because in Phase 4.8b Kafka composition did not exist and
// ADR 0009 declines a service abstraction until two services prove a shared
// contract. Phase 6.1c added `DiagnoseKafka`, so the literal assertion is now
// false by design — and deleting it outright would have thrown away the
// architecture property it was really protecting.
//
// **That property is separation, not absence.** ADR 0009 forbids central
// service-conditional sprawl: what must never appear is a file that branches on
// which service is being diagnosed, or a registry that dispatches between them.
// Two concrete composition roots, one per service, in their own files, is
// exactly the shape that record authorizes.
//
// So this now asserts the two things that still matter: PostgreSQL's files may
// not reach Kafka's layers or the reverse, and neither may import the other's
// service vocabulary. `select.go` and `target.go` are shared by both and hold
// no service import at all, which the allowlist below encodes.
func TestTheCompositionRootKeepsItsServicesInSeparateFiles(t *testing.T) {
	root := filepath.Join(repoRoot(t), "internal", "app")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading the composition root: %v", err)
	}

	// Which service each production file is allowed to reach. A file absent from
	// this map may reach neither, which is how the shared helpers stay shared.
	owner := map[string]string{
		"postgres.go":          "postgres",
		"kafka.go":             "kafka",
		"kafkacompleteness.go": "kafka",
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		allowed := owner[e.Name()]
		for _, imported := range parseFile(t, filepath.Join(root, e.Name())).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			for _, service := range []string{"kafka", "postgres"} {
				serviceImport := strings.Contains(path, "adapter/"+service) ||
					strings.Contains(path, "diagnosis/"+service) ||
					strings.Contains(path, "service/"+service)
				if serviceImport && service != allowed {
					t.Errorf("%s imports %s.\n\n"+
						"Each service is composed in its own file. A file that reached "+
						"both would be where a service switch grows, which ADR 0009 "+
						"refuses; a shared helper reaches neither.", e.Name(), path)
				}
			}
		}
	}
}

// TestNoProductionCodeSelectsATransportPath pins that the selection policy
// ADR 0024 removed has not reappeared one layer up.
//
// The chain returns every completed path and ranks none. Indexing the slice is a
// choice; making it in production before ADR 0041 would be making it invisibly,
// which is the specific failure ADR 0024 §3 records.
func TestNoProductionCodeSelectsATransportPath(t *testing.T) {
	for _, path := range productionGoFiles(t) {
		if strings.Contains(path, filepath.Join("internal", "probe", "transport")) {
			continue // the chain owns its own slice
		}

		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			index, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			call, ok := index.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Continuations" {
				return true
			}
			t.Errorf("%s indexes Continuations(); path selection is deferred to ADR 0041", path)
			return true
		})
	}
}

// TestNoProductionAddressFamilyPreference pins that nothing sorts or filters
// resolved addresses by family.
//
// ADR 0024 §3's whole finding was that canonical ordering *is* an IPv4
// preference when it is used as a selector. A preference expressed directly
// would be the same policy, stated.
func TestNoProductionAddressFamilyPreference(t *testing.T) {
	banned := map[string]bool{"Is4": true, "Is6": true, "Is4In6": true}

	for _, path := range productionGoFiles(t) {
		// The probes legitimately classify addresses to record them.
		if strings.Contains(path, filepath.Join("internal", "probe")) {
			continue
		}
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && banned[sel.Sel.Name] {
				t.Errorf("%s inspects an address family; svcdoctor expresses no preference", path)
			}
			return true
		})
	}
}

// TestNoProductionServiceRegistry pins that service selection has not been
// invented on the way past.
//
// ADR 0009 puts it at a single composition root that does not exist yet.
func TestNoProductionServiceRegistry(t *testing.T) {
	banned := []string{"ServiceRegistry", "AdapterRegistry", "RunPostgres", "PostgresRunner",
		"ExecutionPlan", "RunPlan"}

	for _, path := range productionGoFiles(t) {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			var name string
			switch decl := n.(type) {
			case *ast.TypeSpec:
				name = decl.Name.Name
			case *ast.FuncDecl:
				name = decl.Name.Name
			default:
				return true
			}
			for _, b := range banned {
				if name == b {
					t.Errorf("%s declares %s; service composition is deferred to ADR 0041",
						path, b)
				}
			}
			return true
		})
	}
}

// TestNoProductionSQL restates the no-SQL contract over the whole tree.
//
// The session step already carries an AST guard over its own sources. This one
// widens it: composing the slice is exactly the moment somebody would be tempted
// to add a health query.
func TestNoProductionSQL(t *testing.T) {
	fragments := []string{"SELECT ", "select 1", "pg_is_in_recovery", "current_database",
		"SHOW ", "INSERT ", "UPDATE ", "DELETE "}

	for _, path := range productionGoFiles(t) {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, f := range fragments {
				if strings.Contains(lit.Value, f) {
					t.Errorf("%s contains a SQL-shaped literal %s", path, lit.Value)
				}
			}
			return true
		})
	}
}

// TestDiagnosisRemainsPure restates the purity boundary from outside the
// package, where a reader of the composed path will look for it.
func TestDiagnosisRemainsPure(t *testing.T) {
	root := repoRoot(t)
	forbidden := map[string]bool{
		"net": true, "net/http": true, "crypto/tls": true, "os": true, "os/exec": true,
		"database/sql": true, "math/rand": true, "math/rand/v2": true,
		"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres":      true,
		"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire": true,
		"github.com/hakanaltindag/svcdoctor/internal/probe":                 true,
		"github.com/hakanaltindag/svcdoctor/internal/security":              true,
	}

	pkg, err := gobuild.ImportDir(filepath.Join(root, "internal", "diagnosis", "postgres"), 0)
	if err != nil {
		t.Fatalf("describing the diagnosis package: %v", err)
	}
	for _, imported := range pkg.Imports {
		if forbidden[imported] {
			t.Errorf("internal/diagnosis/postgres imports %s", imported)
		}
	}
}

// TestPostgreSQLFindingCodesLiveOnlyInDiagnosis pins that no POSTGRES_* code is
// spelled anywhere else — the harness included.
//
// A test that hard-codes the string instead of referencing the constant would
// keep passing while the constant changed, which is the quiet way an end-to-end
// suite stops validating anything.
func TestPostgreSQLFindingCodesLiveOnlyInDiagnosis(t *testing.T) {
	root := repoRoot(t)
	allowed := filepath.Join(root, "internal", "diagnosis", "postgres")

	check := func(path string) {
		if strings.HasPrefix(path, allowed) {
			return
		}
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			// Assembled rather than written, so this guard does not match its
			// own source and then report itself.
			needle := `"` + "POSTGRES" + "_"
			if ok && lit.Kind == token.STRING && strings.Contains(lit.Value, needle) {
				t.Errorf("%s spells %s; reference the constant instead", path, lit.Value)
			}
			return true
		})
	}

	for _, path := range productionGoFiles(t) {
		check(path)
	}
	for _, name := range harnessFiles(t) {
		check(filepath.Join(repoRoot(t), "test", "integration", "postgres", name))
	}
}

// TestTheHarnessUsesRealEvidenceOnly pins that the end-to-end path never
// hand-builds a node.
//
// The Phase 4.6b tests over hand-built graphs are the authority on diagnosis
// policy and are untouched. These tests are the authority on whether the policy
// meets what a real server produces, and that claim collapses the moment a node
// is constructed here.
func TestTheHarnessUsesRealEvidenceOnly(t *testing.T) {
	banned := map[string]bool{"NewEvidence": true, "NewGraphBuilder": false}

	root := filepath.Join(repoRoot(t), "test", "integration", "postgres")
	for _, name := range harnessFiles(t) {
		ast.Inspect(parseFile(t, filepath.Join(root, name)), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "domain" {
				return true
			}
			if banned[sel.Sel.Name] {
				t.Errorf("%s calls domain.%s; this suite must obtain evidence from the "+
					"production stages", name, sel.Sel.Name)
			}
			return true
		})
	}
}

// harnessFiles lists this package's own sources.
func harnessFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the harness directory: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestOnlyThePreconditionHelperIndexesAPath keeps the harness honest about the
// thing it exists to avoid.
//
// requireSingleContinuation indexes the slice, once, after proving the slice has
// exactly one entry. Any other call site would be choosing — and choosing is
// what ADR 0024 §3 removed from the chain and ADR 0041 will decide for
// production. A second `[0]` here is how that decision would get made by
// accident.
func TestOnlyThePreconditionHelperIndexesAPath(t *testing.T) {
	root := filepath.Join(repoRoot(t), "test", "integration", "postgres")

	for _, name := range harnessFiles(t) {
		file := parseFile(t, filepath.Join(root, name))

		// Find the byte range of the one function allowed to index.
		var allowedFrom, allowedTo token.Pos
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == "requireSingleContinuation" {
				allowedFrom, allowedTo = fn.Pos(), fn.End()
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			index, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			ident, ok := index.X.(*ast.Ident)
			if !ok || ident.Name != "paths" {
				return true
			}
			if allowedFrom != token.NoPos && index.Pos() >= allowedFrom && index.End() <= allowedTo {
				return true
			}
			t.Errorf("%s indexes a transport path outside requireSingleContinuation; "+
				"selection is a fixture precondition here and ADR 0041's decision in production",
				name)
			return true
		})
	}
}
