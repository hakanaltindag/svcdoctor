package vocabulary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// This package exists so that four strings have one spelling. A test that only
// checked the constants' values would miss the failure mode entirely: the risk
// is not that a value here is wrong, it is that a second copy appears somewhere
// else and the two drift.

// TestTheValuesAreTheReportContract pins the strings themselves.
//
// They moved here from internal/probe/dns, internal/probe/tcp and
// internal/probe/tls, and the move was ownership only. A changed value here is a
// changed report contract and breaks every consumer matching on it, so it is
// asserted literally rather than derived.
func TestTheValuesAreTheReportContract(t *testing.T) {
	for _, c := range []struct {
		got  domain.Step
		want string
	}{
		{StepTargetRequested, "target.requested"},
		{StepDNSLookup, "dns.lookup"},
		{StepTCPConnect, "tcp.connect"},
		{StepTLSHandshake, "tls.handshake"},
	} {
		if string(c.got) != c.want {
			t.Errorf("step = %q, want %q", c.got, c.want)
		}
		if !c.got.Valid() {
			t.Errorf("%q is not a valid step name", c.got)
		}
	}
}

// TestEachCanonicalStringHasExactlyOneOwner is the reason the package exists.
//
// Every production file in the repository is scanned for the four literals. They
// may appear here and nowhere else: a second literal copy is the bug this package
// was created to make impossible, and it would be invisible until a rename split
// one contract into two.
//
// Test files are excluded deliberately. A test asserting that a step is spelled
// "dns.lookup" is exactly the kind of literal that should exist.
func TestEachCanonicalStringHasExactlyOneOwner(t *testing.T) {
	owned := map[string]bool{
		"target.requested": true,
		"dns.lookup":       true,
		"tcp.connect":      true,
		"tls.handshake":    true,
	}

	root := repoRoot(t)
	found := map[string][]string{}

	walkProductionFiles(t, root, func(path string, file *ast.File) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || !owned[value] {
				return true
			}
			found[value] = append(found[value], rel)
			return true
		})
	})

	for value := range owned {
		files := found[value]
		switch {
		case len(files) == 0:
			t.Errorf("%q appears in no production file; the scan is not seeing this "+
				"package and every other assertion here is vacuous", value)
		case len(files) > 1 || !strings.HasPrefix(files[0], filepath.Join("internal", "vocabulary")):
			t.Errorf("%q appears in %v; it must appear only in internal/vocabulary, "+
				"because a second copy is a contract that can drift", value, files)
		}
	}
}

// TestTheProbesAliasRatherThanRedeclare checks the other half of the move.
//
// An alias keeps every existing caller working and keeps one spelling. A
// redeclared constant with the same value would compile, pass every test, and
// silently restore the duplication this package removed — which is why the
// literal scan above is the real guard and this is its readable companion.
func TestTheProbesAliasRatherThanRedeclare(t *testing.T) {
	root := repoRoot(t)

	for _, c := range []struct{ file, name, want string }{
		{filepath.Join("internal", "probe", "dns", "lookup.go"), "StepLookup", "StepDNSLookup"},
		{filepath.Join("internal", "probe", "tcp", "connect.go"), "StepConnect", "StepTCPConnect"},
		{filepath.Join("internal", "probe", "tls", "handshake.go"), "StepHandshake", "StepTLSHandshake"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, c.file), nil,
			parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", c.file, err)
		}

		if !aliasesVocabulary(file, c.name, c.want) {
			t.Errorf("%s does not declare %s as an alias of vocabulary.%s",
				c.file, c.name, c.want)
		}
	}
}

func aliasesVocabulary(file *ast.File, name, want string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != name || len(spec.Values) != 1 {
			return true
		}
		sel, ok := spec.Values[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "vocabulary" && sel.Sel.Name == want {
			found = true
		}
		return true
	})
	return found
}

// TestThisPackageHasNoBehaviour keeps the leaf a leaf.
//
// A vocabulary that grows a function grows a reason to import it from somewhere
// it does not belong, and then a reason to add a second one. The rule is easier
// to hold than to recover.
func TestThisPackageHasNoBehaviour(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "vocabulary")

	entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("globbing: %v", err)
	}

	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				t.Errorf("%s declares func %s; this package holds names and no behaviour",
					filepath.Base(path), fn.Name.Name)
			}
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if path != "github.com/hakanaltindag/svcdoctor/internal/domain" {
				t.Errorf("%s imports %s; this package imports internal/domain and nothing else",
					filepath.Base(path), path)
			}
		}
	}
}

// TestOnlyTheAuthorizedGenericFindingCodesExist keeps the generic claim
// vocabulary closed.
//
// It began as a blanket ban: before ADR 0043 no generic transport finding was
// authorized at all, so any DNS_, TCP_, TLS_ or TARGET_ code was a defect. ADR
// 0043 authorized exactly three, and the guard narrowed rather than disappeared —
// a ban that is deleted the moment it first fires protects nothing.
//
// What it still protects:
//
//   - **a ninth generic code**, added without a record deciding what it may
//     claim — which is the invented diagnostic policy ADR 0017 exists to prevent.
//     ADR 0053 authorized the five TLS codes below and no more; a sixth would be
//     a claim nobody reviewed.
//   - **TARGET_**, which contradicts the namespace convention docs/FINDINGS.md
//     section 1 fixes: generic transport findings use the layer as the namespace.
//
// FailureClass values share these prefixes and are legitimate — they say what
// evidence observed. Only a FindingCode is a claim, so the scan is limited to
// declarations of that type.
func TestOnlyTheAuthorizedGenericFindingCodesExist(t *testing.T) {
	authorized := map[string]bool{
		"DNS_NAME_NOT_RESOLVED":          true,
		"DNS_RESOLUTION_FAILED":          true,
		"TCP_CONNECTION_NOT_ESTABLISHED": true,

		// ADR 0053, implemented in Phase 6.1b. Exactly five, for the six
		// FailureClasses internal/probe/tls actually produces; the two
		// certificate-validity classes share one code. The three declared
		// classes with no producer — TLS_VERSION_MISMATCH,
		// TLS_CLIENT_CERTIFICATE_REQUIRED, TLS_CLIENT_CERTIFICATE_REJECTED —
		// deliberately have none.
		"TLS_ENDPOINT_DOES_NOT_SPEAK_TLS": true,
		"TLS_IDENTITY_MISMATCH":           true,
		"TLS_CHAIN_NOT_TRUSTED":           true,
		"TLS_CERTIFICATE_NOT_VALID_NOW":   true,
		"TLS_HANDSHAKE_NOT_COMPLETED":     true,
	}
	// PostgreSQL's five in-band TLS codes are namespaced POSTGRES_, so none
	// matches a prefix below and this scan governs only the generic vocabulary.
	prefixes := []string{"DNS_", "TCP_", "TLS_", "TARGET_"}

	root := repoRoot(t)
	scanned := 0
	found := map[string]bool{}

	walkProductionFiles(t, root, func(path string, file *ast.File) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || !declaresFindingCode(spec) {
				return true
			}
			scanned++
			for _, value := range spec.Values {
				lit, ok := value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				code, uErr := strconv.Unquote(lit.Value)
				if uErr != nil {
					continue
				}
				if authorized[code] {
					found[code] = true
					continue
				}
				for _, prefix := range prefixes {
					if strings.HasPrefix(code, prefix) {
						t.Errorf("%s declares generic finding code %s, which no record "+
							"authorizes; ADR 0043 fixed exactly three", rel, code)
					}
				}
			}
			return true
		})
	})

	// The control. A scan that recognized no declaration would pass on any
	// repository, including one full of the codes it is meant to reject.
	if scanned == 0 {
		t.Error("no FindingCode declaration was recognized; the scan is vacuous")
	}
	for code := range authorized {
		if !found[code] {
			t.Errorf("%s is authorized but declared nowhere; either the rule was removed "+
				"or this guard no longer sees it", code)
		}
	}
}

// TestNoGenericFindingCodeMirrorsAFailureClass keeps the two vocabularies apart.
//
// FailureClass says what evidence observed; FindingCode says what diagnosis
// claims. A code spelled identically to a class would be indistinguishable from
// an observation in any consumer that matches on strings, and it is how a claim
// vocabulary quietly becomes a second copy of the evidence vocabulary.
//
// This is why the TCP finding is not called TCP_CONNECTION_FAILED, which is a
// real failure class, and why the DNS one is not DNS_NO_ADDRESS.
func TestNoGenericFindingCodeMirrorsAFailureClass(t *testing.T) {
	classes := map[string]bool{}
	for i := 0; ; i++ {
		class := domain.FailureClass(i)
		if !class.Valid() {
			break
		}
		classes[class.String()] = true
	}
	if len(classes) < 30 {
		t.Fatalf("only %d failure classes enumerated; the scan is vacuous", len(classes))
	}

	for _, code := range []string{
		"DNS_NAME_NOT_RESOLVED", "DNS_RESOLUTION_FAILED", "TCP_CONNECTION_NOT_ESTABLISHED",
		// The five generic TLS codes matter most here. They carry no service
		// prefix, so a report holds failureClass and code in the same string
		// shape — and a code that repeated its class's spelling would make the
		// two namespaces indistinguishable to a consumer matching on strings.
		// That hazard is why ADR 0053 rejected TLS_PEER_NOT_TLS and
		// TLS_HANDSHAKE_FAILED as codes; this assertion is what keeps them out.
		"TLS_ENDPOINT_DOES_NOT_SPEAK_TLS", "TLS_IDENTITY_MISMATCH",
		"TLS_CHAIN_NOT_TRUSTED", "TLS_CERTIFICATE_NOT_VALID_NOW",
		"TLS_HANDSHAKE_NOT_COMPLETED",
	} {
		if classes[code] {
			t.Errorf("finding code %s is also a FailureClass name", code)
		}
	}
}

// declaresFindingCode reports whether a value spec declares a domain.FindingCode.
func declaresFindingCode(spec *ast.ValueSpec) bool {
	if sel, ok := spec.Type.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == "FindingCode"
	}
	ident, ok := spec.Type.(*ast.Ident)
	return ok && ident.Name == "FindingCode"
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}

// walkProductionFiles visits every non-test Go file in the module.
func walkProductionFiles(t *testing.T, root string, visit func(path string, file *ast.File)) {
	t.Helper()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		visit(path, file)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
}
