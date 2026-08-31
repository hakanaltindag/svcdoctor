package security_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// The multi-target foundation's structural boundaries.
//
// # Why these are security tests rather than architecture housekeeping
//
// The fleet layer is the first thing in svcdoctor that reads a file describing
// *many* credentials and hands them to *many* endpoints. Three properties keep
// that safe, and none of them is visible in behaviour:
//
//   - the parser cannot construct a secret, because it does not import the
//     package that defines one;
//   - the resolver cannot reveal one, because it is not a wire package;
//   - neither can reach a protocol, because they import no adapter.
//
// Each is a compile-time fact, so each is checked by reading the tree. A
// behavioural test cannot prove any of them: it can only show that a particular
// path did not do the thing today.
//
// Every guard here has a matching non-vacuity proof, because a guard that scans
// a package list which has silently gone empty passes forever.

// fleetPackages are the packages this phase created.
var fleetPackages = []string{
	"internal/fleet/config",
	"internal/fleet/secret",
	"internal/fleet/services/postgres",
	"internal/fleet/services/kafka",
	"internal/fleet/services/redis",
	"internal/fleet/services/rabbitmq",
	"internal/security/secretinput",
}

// fleetCorePackages are the packages that must stay free of every protocol.
//
// The four service packages are deliberately absent: bridging a configuration to
// a composition root is exactly their job, and ADR 0071 section 5's import table
// gives them internal/app. The core is what must not know a service exists.
var fleetCorePackages = []string{
	"internal/fleet/config",
	"internal/fleet/secret",
}

// TestTheConfigPackageCannotConstructASecret is ADR 0072 section 6.
//
// internal/fleet/config does not import internal/security. That is what makes
// "the parser must not reveal secrets" a property of the build rather than a
// rule someone follows: the parser does not decline to build a secret, it has no
// type to build one with.
func TestTheConfigPackageCannotConstructASecret(t *testing.T) {
	imports := importsOfPackage(t, "internal/fleet/config")
	if len(imports) == 0 {
		t.Fatal("no imports were found; this guard would pass vacuously")
	}

	for _, path := range imports {
		if path == "github.com/hakanaltindag/svcdoctor/internal/security" ||
			strings.HasPrefix(path, "github.com/hakanaltindag/svcdoctor/internal/security/") {
			t.Errorf("internal/fleet/config imports %s.\n\n"+
				"The configuration layer holds credential *references* and never material "+
				"(ADR 0072 §6). It cannot build a security.Secret because the type is not in "+
				"scope, and that is the whole guarantee — a parser that could construct one "+
				"would be one refactor away from retaining one.", path)
		}
	}
}

// TestTheFleetCoreReachesNoProtocol keeps orchestration above the adapters.
//
// It is the fleet-layer form of the rule every composition root already obeys:
// an adapter is reached through internal/app, never around it.
func TestTheFleetCoreReachesNoProtocol(t *testing.T) {
	forbidden := []struct{ prefix, why string }{
		{"github.com/hakanaltindag/svcdoctor/internal/adapter/",
			"adapters understand protocols; the fleet core schedules and parses"},
		{"github.com/hakanaltindag/svcdoctor/internal/diagnosis/",
			"diagnosis consumes frozen evidence and must not be reachable from a parser"},
		{"github.com/hakanaltindag/svcdoctor/internal/probe/",
			"probes perform I/O; configuration validation performs none"},
		{"github.com/hakanaltindag/svcdoctor/internal/render/",
			"renderers present a finished report"},
		{"github.com/twmb/franz-go/",
			"the Kafka protocol library belongs to one wire package"},
	}

	found := false
	for _, pkg := range fleetCorePackages {
		imports := importsOfPackage(t, pkg)
		if len(imports) > 0 {
			found = true
		}
		for _, path := range imports {
			for _, bad := range forbidden {
				if strings.HasPrefix(path, bad.prefix) {
					t.Errorf("%s imports %s: %s", pkg, path, bad.why)
				}
			}
		}
	}
	if !found {
		t.Fatal("no fleet core imports were found; this guard would pass vacuously")
	}
}

// TestTheFleetCoreOpensNoSocket proves configuration validation cannot dial.
//
// The behavioural half is in internal/fleet/config, where four unresolvable
// hosts validate in microseconds. This is the stronger half: a package that
// cannot name `net` cannot resolve or connect no matter what is added to it.
func TestTheFleetCoreOpensNoSocket(t *testing.T) {
	forbidden := map[string]string{
		"net":           "resolving and dialling belong to internal/probe",
		"net/http":      "there is no remote configuration source (ADR 0071 §10)",
		"net/url":       "a configuration is a file path, never a URL",
		"os/exec":       "there is no exec credential provider (ADR 0072 §13)",
		"text/template": "there is no templating engine (ADR 0071 §8.3)",
		"html/template": "there is no templating engine (ADR 0071 §8.3)",
	}

	found := false
	for _, pkg := range fleetPackages {
		imports := importsOfPackage(t, pkg)
		if len(imports) > 0 {
			found = true
		}
		for _, path := range imports {
			if why, bad := forbidden[path]; bad {
				t.Errorf("%s imports %q: %s", pkg, path, why)
			}
		}
	}
	if !found {
		t.Fatal("no fleet imports were found; this guard would pass vacuously")
	}
}

// TestOnlyTheConfigPackageImportsTheYAMLLibrary is ADR 0071 section 3.3.
//
// A dependency exactly one package can name cannot spread by convenience, which
// is the containment ADR 0025 gives the Kafka protocol library. ServiceNode is
// what makes it hold without taking decoding away from services: a service
// receives an opaque subtree, so a fifth service adds no importer.
func TestOnlyTheConfigPackageImportsTheYAMLLibrary(t *testing.T) {
	const yamlModule = "go.yaml.in/yaml/v3"
	const allowed = "internal/fleet/config"

	importers := map[string]bool{}
	for _, pkg := range allProductionPackages(t) {
		for _, path := range importsOfPackage(t, pkg) {
			if strings.HasPrefix(path, yamlModule) {
				importers[pkg] = true
			}
		}
	}

	if !importers[allowed] {
		t.Fatalf("no package imports %s; this guard would pass vacuously", yamlModule)
	}
	for pkg := range importers {
		if pkg != allowed {
			t.Errorf("%s imports %s.\n\n"+
				"ADR 0071 §3.3 confines the YAML library to %s. A service decodes its own "+
				"configuration through config.ServiceNode, which exists precisely so that "+
				"decoding stays with the service while the dependency does not spread.",
				pkg, yamlModule, allowed)
		}
	}
}

// TestTheFleetLayerNeverRevealsASecret keeps the Reveal count at four.
//
// `forbidigo` already fails the build on a call site outside a wire package, so
// this is a second, independent statement of the same fact — and it is the one
// that reads as a sentence about the fleet layer rather than as a lint rule.
func TestTheFleetLayerNeverRevealsASecret(t *testing.T) {
	found := false
	for _, pkg := range fleetPackages {
		for _, path := range productionFilesIn(t, pkg) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			found = true
			if strings.Contains(string(source), "security.Reveal(") {
				t.Errorf("%s calls security.Reveal.\n\n"+
					"Revealing is the adapter wire packages' single privilege (ADR 0027). "+
					"The fleet layer resolves material and binds it to an endpoint; the "+
					"adapter decides when a byte of it crosses a wire.", path)
			}
		}
	}
	if !found {
		t.Fatal("no fleet production source was found; this guard would pass vacuously")
	}
}

// TestOnlyTheResolverReadsTheEnvironment is ADR 0072 section 4's structural half.
//
// ADR 0049 §5 rejected environment variables as a leaf command's credential
// source, and Phase 8.2-R3 removed a `--password-env` flag that contradicted it.
// Fleet configuration may name one — a written, target-bound, reviewable
// reference is a different object from an ambient flag — and the way that stays
// true is that the read happens in one package which is not internal/cli.
func TestOnlyTheResolverReadsTheEnvironment(t *testing.T) {
	envReaders := []string{"os.Getenv(", "os.LookupEnv(", "os.Environ(", "os.ExpandEnv("}
	const allowed = "internal/fleet/secret"

	sawAllowed := false
	for _, pkg := range fleetPackages {
		for _, path := range productionFilesIn(t, pkg) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, reader := range envReaders {
				if !strings.Contains(string(source), reader) {
					continue
				}
				if pkg == allowed {
					sawAllowed = true
					continue
				}
				t.Errorf("%s calls %s.\n\n"+
					"Environment access exists at exactly one place in the whole "+
					"configuration path: resolving a `password: {env: NAME}` reference in "+
					"%s. Anywhere else it is ambient configuration, which ADR 0071 §8.3 "+
					"refuses along with ${VAR} interpolation.", path, reader, allowed)
			}
		}
	}
	if !sawAllowed {
		t.Fatalf("no environment read was found in %s; this guard would pass vacuously "+
			"and the env credential source would be unimplemented", allowed)
	}
}

// TestTheCLIStillReadsNoEnvironmentVariable keeps the leaf commands unchanged.
//
// Duplicating internal/cli's own guard on purpose. Phase 9.1A adds an
// environment-backed credential source to the *fleet* layer, and the most
// plausible way that decision leaks is someone deciding the leaf commands should
// have it too. This is the sentence that says no, from the outside.
func TestTheCLIStillReadsNoEnvironmentVariable(t *testing.T) {
	files := productionFilesIn(t, "internal/cli")
	if len(files) == 0 {
		t.Fatal("no internal/cli source was found; this guard would pass vacuously")
	}
	for _, path := range files {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, reader := range []string{
			"os.Getenv(", "os.LookupEnv(", "os.Environ(", "os.ExpandEnv(",
		} {
			if strings.Contains(string(source), reader) {
				t.Errorf("%s calls %s; ADR 0049 §5 keeps every leaf command's credential "+
					"sources to --password-file and --password-stdin", path, reader)
			}
		}
	}
}

// TestTheFleetLayerHasNoSecretCache is ADR 0072 section 8.
//
// A cache would have to be keyed by the reference, and a reference is not an
// authority. The behavioural proof is in internal/fleet/secret, where changing a
// file between two resolutions changes the secret; this is the structural one,
// and it catches the shapes a behavioural test would miss — a package-level map,
// a sync.Map, a singleflight group.
func TestTheFleetLayerHasNoSecretCache(t *testing.T) {
	cacheShapes := []struct{ text, why string }{
		{"sync.Map", "a concurrent map in the credential path is a cache"},
		{"singleflight", "deduplicating resolutions is caching them"},
		{"sync.Once", "resolving once and reusing the result is a cache"},
	}

	found := false
	for _, pkg := range []string{"internal/fleet/secret", "internal/fleet/config"} {
		for _, path := range productionFilesIn(t, pkg) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			found = true
			for _, shape := range cacheShapes {
				if strings.Contains(string(source), shape.text) {
					t.Errorf("%s contains %q: %s.\n\n"+
						"Two targets naming one variable resolve it twice (ADR 0072 §8). "+
						"Reading an environment variable twice is free; a credential object "+
						"shared between two endpoints is a SecretFor mismatch waiting to "+
						"surface at a wire boundary.", path, shape.text, shape.why)
				}
			}
		}
	}
	if !found {
		t.Fatal("no source was scanned; this guard would pass vacuously")
	}
}

// TestTheResolverHoldsNoState proves the resolver cannot accumulate anything.
//
// A struct with no fields cannot cache, cannot count and cannot remember. That
// is a stronger statement than "it does not today", and it is why the resolver
// is a bare struct rather than an interface with one implementation — an
// interface is a seam a caching implementation could be substituted through.
func TestTheResolverHoldsNoState(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "internal/fleet/secret/secret.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var checked bool
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "Resolver" {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			t.Fatalf("Resolver is %T, want a struct", spec.Type)
		}
		checked = true
		if structType.Fields != nil && len(structType.Fields.List) > 0 {
			t.Errorf("Resolver has %d field(s); it must have none, so that it cannot "+
				"accumulate a secret, a cache or a count between calls",
				len(structType.Fields.List))
		}
		return false
	})
	if !checked {
		t.Fatal("no Resolver type was found; this guard would pass vacuously")
	}
}

// TestTheFleetGuardsCanFail is the non-vacuity proof for this file.
//
// Each scan is run against a package that genuinely has the thing being looked
// for, so a helper that silently returned nothing would be caught here rather
// than reported as a clean build everywhere.
func TestTheFleetGuardsCanFail(t *testing.T) {
	t.Run("importsOfPackage finds a known import", func(t *testing.T) {
		imports := importsOfPackage(t, "internal/fleet/config")
		if !containsPath(imports, "go.yaml.in/yaml/v3") {
			t.Error("the config package must import the YAML library; the scan found no " +
				"trace of it, so every import guard in this file is vacuous")
		}
	})

	t.Run("productionFilesIn finds files and excludes tests", func(t *testing.T) {
		files := productionFilesIn(t, "internal/fleet/secret")
		if len(files) == 0 {
			t.Fatal("no production files were found")
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				t.Errorf("%s is a test file; guards must not scan their own fixtures", path)
			}
		}
	})

	t.Run("the environment scan finds the one legitimate reader", func(t *testing.T) {
		var found bool
		for _, path := range productionFilesIn(t, "internal/fleet/secret") {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if strings.Contains(string(source), "os.LookupEnv(") {
				found = true
			}
		}
		if !found {
			t.Error("the resolver reads no environment variable, so the guard that " +
				"confines environment access to it proves nothing")
		}
	})

	t.Run("the Reveal scan can see a real call site", func(t *testing.T) {
		// A wire package genuinely calls Reveal. If this scan cannot find it
		// there, it could not find one in the fleet layer either.
		var found bool
		for _, path := range productionFilesIn(t, "internal/adapter/redis/wire") {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if strings.Contains(string(source), "security.Reveal(") {
				found = true
			}
		}
		if !found {
			t.Error("no security.Reveal call was found in a wire package that has one; " +
				"the fleet Reveal guard is therefore vacuous")
		}
	})
}

// TestTheGenericCoreNamesNoService is ADR 0071 section 6.3's extensibility claim.
//
// # What would break without it
//
// The failure this prevents is gradual and reads as helpfulness at every step: a
// PostgreSQL default here, a Kafka special case there, and eventually the
// `if kafka {} else if postgres {}` sprawl docs/ARCHITECTURE.md's extensibility
// rule names as the forbidden direction. Each individual edit looks reasonable.
//
// So the core does not get to say the words. A service name reaches it only as a
// Factory's Kind() at runtime, which is data, and adding a fifth service
// therefore requires no edit here at all.
func TestTheGenericCoreNamesNoService(t *testing.T) {
	services := []string{"postgres", "kafka", "redis", "rabbitmq", "mysql", "elasticsearch"}

	found := false
	for _, pkg := range fleetCorePackages {
		for _, path := range productionFilesIn(t, pkg) {
			file := parseFile(t, path)
			found = true
			for _, literal := range stringLiterals(file) {
				for _, service := range services {
					if strings.EqualFold(literal, service) {
						t.Errorf("%s contains the string literal %q.\n\n"+
							"The generic configuration core dispatches through a registry of "+
							"factories (ADR 0071 §6.3). A service name written into it is the "+
							"first line of the central branching the extensibility rule "+
							"forbids, and it means a fifth service would require editing this "+
							"package.", relative(t, path), literal)
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("no core source was scanned; this guard would pass vacuously")
	}
}

// TestAValidatedConfigRetainsNoRawBytes keeps the document out of the model.
//
// A []byte reachable from Config would be the raw configuration — which holds
// every credential reference in the run and, if an operator ever wrote one
// wrongly, a plaintext password. ADR 0074 section 8.3 refuses to serialize it;
// this refuses to retain it, which is the earlier and stronger of the two.
func TestAValidatedConfigRetainsNoRawBytes(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, path string) {
		if typ == nil || seen[typ] {
			return
		}
		seen[typ] = true
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			t.Errorf("config.Config reaches a byte slice at %s.\n\n"+
				"A validated configuration holds values, never the document they came "+
				"from: the raw bytes carry every credential reference in the run.", path)
			return
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := range typ.NumField() {
				walk(typ.Field(i).Type, path+"."+typ.Field(i).Name)
			}
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			walk(typ.Elem(), path+"[]")
		}
	}
	walk(reflect.TypeOf(config.Config{}), "Config")
}

// importsOfPackage returns every import path in one package's production files.
func importsOfPackage(t *testing.T, pkg string) []string {
	t.Helper()

	var out []string
	for _, path := range productionFilesIn(t, pkg) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, spec := range file.Imports {
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote %s in %s: %v", spec.Path.Value, path, err)
			}
			out = append(out, value)
		}
	}
	return out
}

// productionFilesIn lists a package's non-test Go files.
func productionFilesIn(t *testing.T, pkg string) []string {
	t.Helper()

	dir := filepath.Join(repositoryRoot(t), pkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out
}

// allProductionPackages lists every package under internal/ and cmd/.
func allProductionPackages(t *testing.T) []string {
	t.Helper()

	root := repositoryRoot(t)
	var out []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if len(productionFilesIn(t, rel)) > 0 {
				out = append(out, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no production packages were found")
	}
	return out
}

// containsPath reports whether haystack holds needle.
//
// Named for its use rather than generically, because test/security already has a
// `contains` for the dependency guard and two helpers with one name in one
// package is how a later reader picks the wrong one.
func containsPath(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}
