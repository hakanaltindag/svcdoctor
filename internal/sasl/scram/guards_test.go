package scram

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file is the positive half of the Phase 6.2 gate transition.
//
// Until Phase 6.2, test/security/kafka_production_reachability_test.go carried
// TestNoSharedSCRAMPackageExists, which failed the build if this package
// existed at all. That guard was not deleted and then replaced: it was replaced
// **in the same change-set that created this package**, because a commit in
// which neither the negative guard nor these positive ones hold is exactly the
// window ADR 0056 section 13 exists to close.
//
// Everything below asserts a property of the source. Each one was mutation-
// tested in both directions during Phase 6.2 — a guard that cannot fail is
// worse than no guard, because it reads as though it protects something.

// productionFiles returns this package's non-test Go files.
func productionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		t.Fatal("no production files found; this guard would pass vacuously")
	}
	sort.Strings(out)
	return out
}

func parseProduction(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, name := range productionFiles(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = file
	}
	return fset, files
}

// TestSharedCoreImportsAreExactlyTheAllowlist pins the six imports ADR 0056
// section 10 accepted, and fails on any seventh.
//
// The depguard rule in .golangci.yml enforces the same thing from the other
// direction. Two independent guards, because this is the boundary the whole
// Model D decision rests on: a core that could import internal/security could
// call Reveal, and a core that could import net could perform I/O.
func TestSharedCoreImportsAreExactlyTheAllowlist(t *testing.T) {
	allowed := map[string]bool{
		"crypto/hmac":     true, // HMAC-SHA-256, and Equal for the constant-time comparison
		"crypto/rand":     true, // the client nonce, and the only entropy source reachable here
		"crypto/sha256":   true, // Sum256 for StoredKey, New for HMAC
		"encoding/base64": true, // salt decode, proof and nonce encode
		"errors":          true, // the sentinels
		"strconv":         true, // ParseUint for the iteration count
	}

	_, files := parseProduction(t)
	used := map[string]bool{}

	for name, file := range files {
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquoting import %s: %v", name, spec.Path.Value, err)
			}
			used[path] = true
			if !allowed[path] {
				t.Errorf("%s imports %q.\n\n"+
					"The shared SCRAM core's import set is fixed by ADR 0056 section 10. "+
					"internal/security would put Reveal in reach, net would allow I/O, fmt "+
					"would allow a peer's bytes into an error, and crypto/pbkdf2 would mean "+
					"the core derives from a password it must never receive.", name, path)
			}
		}
	}

	for path := range allowed {
		if !used[path] {
			t.Errorf("the allowlist permits %q but nothing imports it; "+
				"an allowlist entry with no user is a widening nobody asked for", path)
		}
	}
}

// TestSharedCoreReachesNoOtherPackage is the sharper half of the import guard.
//
// The allowlist above is a list of names. This asserts the shape: not one
// import path contains a slash-prefixed svcdoctor package, so the core cannot
// reach an adapter, a probe, diagnosis, render, app, service or security no
// matter what a future allowlist edit permits.
func TestSharedCoreReachesNoOtherPackage(t *testing.T) {
	_, files := parseProduction(t)
	for name, file := range files {
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if strings.Contains(path, "svcdoctor") {
				t.Errorf("%s imports %q; the shared core is a leaf and imports no svcdoctor package", name, path)
			}
		}
	}
}

// TestSharedCoreNamesNoCredentialSymbol proves the core cannot open a secret.
//
// Reveal and SecretFor are unreachable here because internal/security is not
// importable, so this is belt and braces — but it is cheap, and it fails on the
// first edit that tries, rather than on the import that would have enabled it.
func TestSharedCoreNamesNoCredentialSymbol(t *testing.T) {
	forbidden := map[string]string{
		"Reveal":     "the shared core never opens a secret; Reveal belongs to a wire package",
		"SecretFor":  "resolving a secret is an adapter's job, after the endpoint binding",
		"NewSecret":  "the shared core mints no credential",
		"Credential": "the shared core holds no credential",
		"Secret":     "the shared core holds no secret",
	}

	_, files := parseProduction(t)
	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if reason, banned := forbidden[ident.Name]; banned {
				t.Errorf("%s names %q: %s", name, ident.Name, reason)
			}
			return true
		})
	}
}

// TestDerivationIsInvokedExactlyOnceInSource is the structural half of the
// callback cardinality contract.
//
// The behavioural half — TestRejectedServerFirstNeverDerives and the state
// machine tests — proves the callback does not run on any rejection path. This
// proves it *cannot*, by pinning the source: one call expression, in no loop and
// in no goroutine. A future edit that adds a retry, a second attempt or a
// concurrent derivation fails here before any test has to catch it at runtime.
func TestDerivationIsInvokedExactlyOnceInSource(t *testing.T) {
	fset, files := parseProduction(t)

	calls := 0
	for name, file := range files {
		// Track the loop and goroutine bodies so a call inside one is caught by
		// position rather than by a fragile parent pointer.
		var loops, routines []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			switch n.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				loops = append(loops, n)
			case *ast.GoStmt:
				routines = append(routines, n)
			}
			return true
		})

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "derive" {
				return true
			}
			calls++
			line := fset.Position(call.Pos()).Line

			for _, loop := range loops {
				if loop.Pos() < call.Pos() && call.End() < loop.End() {
					t.Errorf("%s:%d invokes the derivation callback inside a loop; "+
						"one exchange derives exactly once", name, line)
				}
			}
			for _, routine := range routines {
				if routine.Pos() <= call.Pos() && call.End() <= routine.End() {
					t.Errorf("%s:%d invokes the derivation callback in a goroutine; "+
						"it must run synchronously inside Continue", name, line)
				}
			}
			return true
		})
	}

	if calls != 1 {
		t.Errorf("found %d call expression(s) on the derivation callback, want exactly 1.\n\n"+
			"ADR 0056 section 4 makes 'exactly once on success, zero on every rejection' a "+
			"property of the source rather than of a comment.", calls)
	}
}

// TestSharedCoreStartsNoGoroutine backs the callback contract's asynchronous
// half and the package's no-I/O posture at once.
func TestSharedCoreStartsNoGoroutine(t *testing.T) {
	fset, files := parseProduction(t)
	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			if stmt, ok := n.(*ast.GoStmt); ok {
				t.Errorf("%s:%d starts a goroutine; the shared core is a synchronous pure "+
					"function over bytes", name, fset.Position(stmt.Pos()).Line)
			}
			return true
		})
	}
}

// TestStateHoldsNothingItMustNot pins the State struct's fields by name and
// shape: none exported, none a function type, none a pointer or interface that
// could smuggle a connection or a callback in.
func TestStateHoldsNothingItMustNot(t *testing.T) {
	_, files := parseProduction(t)

	found := false
	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok || spec.Name.Name != "State" {
				return true
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s: State is not a struct", name)
			}
			found = true

			for _, field := range structType.Fields.List {
				for _, fieldName := range field.Names {
					if fieldName.IsExported() {
						t.Errorf("State.%s is exported; every field of the state is unexported "+
							"so that no caller can read credential-derived material off it", fieldName.Name)
					}
				}
				switch field.Type.(type) {
				case *ast.FuncType:
					t.Error("State has a function-typed field; the derivation callback must " +
						"never be retained (ADR 0056 section 4)")
				case *ast.InterfaceType:
					t.Error("State has an interface-typed field; that is how a net.Conn or a " +
						"logger would arrive")
				case *ast.StarExpr:
					t.Error("State has a pointer field; the retained set is two strings and a " +
						"byte slice (ADR 0056 section 6)")
				}
			}
			return false
		})
	}
	if !found {
		t.Fatal("State was not found; this guard would pass vacuously")
	}
}

// TestStateHasNoFormattingMethod proves the state cannot print itself.
//
// A String, GoString or Format method on a value holding an expected server
// signature is one %v away from putting credential-derived material into a log
// line somebody added for debugging.
func TestStateHasNoFormattingMethod(t *testing.T) {
	_, files := parseProduction(t)
	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			switch fn.Name.Name {
			case "String", "GoString", "Format", "MarshalJSON", "MarshalText":
				t.Errorf("%s declares %s on a shared-core type; the state must not be able "+
					"to render itself", name, fn.Name.Name)
			}
		}
	}
}

// TestExportedSurfaceIsExactlyTheContract pins what this package offers.
//
// ADR 0056 section 2 fixed the surface deliberately small. Anything appearing
// here that the contract does not name is a widening, and the two most likely
// widenings are both dangerous: an exported nonce seam a production caller could
// set, and an exported helper that takes a password "just for tests".
func TestExportedSurfaceIsExactlyTheContract(t *testing.T) {
	want := map[string]bool{
		// Constants.
		"MechanismSHA256": true,
		"MaxIterations":   true,
		"DerivedKeyLen":   true,
		"GS2Header":       true,
		// Types.
		"Username": true,
		"Derive":   true,
		"State":    true,
		// Functions and methods.
		"Begin":    true,
		"Continue": true,
		"Verify":   true,
		// Sentinels.
		"ErrMalformedMessage":        true,
		"ErrUnexpectedResponse":      true,
		"ErrMessageTooLarge":         true,
		"ErrUsernameUnsupported":     true,
		"ErrIterationsUnsupported":   true,
		"ErrNoDerivation":            true,
		"ErrDerivationFailed":        true,
		"ErrDerivedKeyLength":        true,
		"ErrRejected":                true,
		"ErrServerSignatureMismatch": true,
		"ErrWrongStep":               true,
	}

	got := map[string]bool{}
	_, files := parseProduction(t)
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					got[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							got[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, ident := range s.Names {
							if ident.IsExported() {
								got[ident.Name] = true
							}
						}
					}
				}
			}
		}
	}

	for name := range got {
		if !want[name] {
			t.Errorf("%s is exported but is not in ADR 0056's accepted surface", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("%s is in ADR 0056's accepted surface but is not exported", name)
		}
	}
}

// TestSASLFamilyHoldsOnlySCRAM keeps internal/sasl from becoming the generic
// SASL framework ADR 0056 section 1 refuses.
//
// A family directory is exactly how one would begin: internal/sasl/plain, then
// internal/sasl/common, then a mechanism interface, and the SCRAM core stops
// being a leaf that imports nothing.
func TestSASLFamilyHoldsOnlySCRAM(t *testing.T) {
	family, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving internal/sasl: %v", err)
	}
	entries, err := os.ReadDir(family)
	if err != nil {
		t.Fatalf("reading internal/sasl: %v", err)
	}

	seen := 0
	for _, entry := range entries {
		if entry.IsDir() {
			if entry.Name() != "scram" {
				t.Errorf("internal/sasl contains %q. Phase 6.2 is SCRAM-SHA-256 only, and "+
					"internal/sasl may hold nothing but scram/ (ADR 0056 section 1).", entry.Name())
			}
			seen++
			continue
		}
		if strings.HasSuffix(entry.Name(), ".go") {
			t.Errorf("internal/sasl/%s exists; the family level holds no Go code, because a "+
				"shared SASL package is the framework this phase declined to build", entry.Name())
		}
	}
	if seen != 1 {
		t.Fatalf("found %d directories under internal/sasl, want exactly 1 (scram)", seen)
	}
}

// TestVerifierComparisonIsConstantTime pins hmac.Equal at the one comparison
// that matters.
//
// The behavioural tests cannot catch this on their own: replacing hmac.Equal
// with `==`, bytes.Equal or a string comparison produces identical results for
// every input and differs only in timing. A source guard is the only mechanism
// that fails on the substitution, which is why this one exists alongside the
// import allowlist rather than relying on it.
func TestVerifierComparisonIsConstantTime(t *testing.T) {
	fset, files := parseProduction(t)

	equals := 0
	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			line := fset.Position(call.Pos()).Line

			if pkg.Name == "bytes" && sel.Sel.Name == "Equal" {
				t.Errorf("%s:%d compares with bytes.Equal; the server verifier is compared "+
					"with hmac.Equal, which is constant-time", name, line)
			}
			if pkg.Name == "hmac" && sel.Sel.Name == "Equal" {
				equals++
			}
			return true
		})
	}

	if equals != 1 {
		t.Errorf("found %d hmac.Equal call(s), want exactly 1.\n\n"+
			"The server signature comparison is the only place a credential-derived value "+
			"is compared against peer input, and it must stay constant-time.", equals)
	}
}
