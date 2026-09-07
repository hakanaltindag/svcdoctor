package security_test

import (
	"go/ast"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The Kubernetes dependency boundary, asserted from outside the packages that
// hold it.
//
// # Why these are security tests
//
// client-go brings about 36 modules into a process that holds plaintext
// credentials, and it brings capabilities svcdoctor has refused: a credential
// plugin runner, a full clientset, a watch machinery, a proxy-aware transport.
// ADR 0094 authorized the dependency **behind an allowlist**, and an allowlist
// that nothing checks is a comment.
//
// depguard enforces the same two properties at lint time. These are the
// independent statement of them, in the repository's own vocabulary, and they
// catch the case a lint configuration cannot: an edit to `.golangci.yml` itself.

// kubernetesLibraryImporter is the only package permitted to import k8s.io.
const kubernetesLibraryImporter = "internal/adapter/kubernetes/client"

// kubernetesClientAllowlist is the ten import paths ADR 0094 section 2.1 enumerated.
//
// **Ten paths on nine rows.** PHASE121A §4.4's table gives one row to
// `k8s.io/api/core/v1` and `k8s.io/api/discovery/v1` together — they are the two
// object groups this adapter reads — which is where the frozen records' phrase
// "nine-package allowlist" comes from. The set below is that table's contents,
// path for path, and nothing was added to make current code pass.
//
// **The refusals matter more than the permissions**, and each is a capability
// rather than a size: the full `Clientset` puts every group and verb one method
// call away; `dynamic` puts every resource there; the discovery client makes a
// round trip the budget did not account for; informers, listers and tools/cache
// are a cache and a watch inside a process that runs once and exits; and every
// `plugin/pkg/client/auth` package exists to execute or delegate the
// authentication this contract refuses.
var kubernetesClientAllowlist = map[string]bool{
	"k8s.io/client-go/rest":                          true,
	"k8s.io/client-go/tools/clientcmd":               true,
	"k8s.io/client-go/tools/clientcmd/api":           true,
	"k8s.io/client-go/kubernetes/typed/core/v1":      true,
	"k8s.io/client-go/kubernetes/typed/discovery/v1": true,
	"k8s.io/api/core/v1":                             true,
	"k8s.io/api/discovery/v1":                        true,
	"k8s.io/apimachinery/pkg/apis/meta/v1":           true,
	"k8s.io/apimachinery/pkg/api/errors":             true,
	"k8s.io/apimachinery/pkg/labels":                 true,
}

// TestOnlyTheKubernetesClientImportsClientGo is ADR 0094 section 2.10.
//
// It is the same property TestOnlyTheConfigPackageImportsTheYAMLLibrary states
// for YAML, and it is enforced for a stronger reason: a YAML decoder parses
// bytes, and a Kubernetes client speaks to a control plane with a credential.
func TestOnlyTheKubernetesClientImportsClientGo(t *testing.T) {
	importers := map[string]bool{}
	for _, pkg := range allProductionPackages(t) {
		for _, path := range importsOfPackage(t, pkg) {
			if strings.HasPrefix(path, "k8s.io/") || strings.HasPrefix(path, "sigs.k8s.io/") {
				importers[pkg] = true
			}
		}
	}

	if !importers[kubernetesLibraryImporter] {
		t.Fatalf("no package imports a Kubernetes library; this guard would pass vacuously "+
			"and %s would be unimplemented", kubernetesLibraryImporter)
	}
	for pkg := range importers {
		if pkg != kubernetesLibraryImporter {
			t.Errorf("%s imports a Kubernetes library.\n\n"+
				"ADR 0094 §2.10 confines every k8s.io package to %s. Every other layer "+
				"consumes svcdoctor's own normalized values, which is what keeps a "+
				"control-plane client out of the diagnosis, the renderer, the scheduler "+
				"and the domain model.", pkg, kubernetesLibraryImporter)
		}
	}
}

// TestTheKubernetesClientImportsAreExactlyTheAllowlist.
//
// It reads the package's own production sources, so it states the property in the
// direction the ADR wrote it: **these ten, and nothing else.** An eleventh would
// need a decision, and this is where that decision has to be written down.
func TestTheKubernetesClientImportsAreExactlyTheAllowlist(t *testing.T) {
	seen := map[string]bool{}
	scanned := 0

	for _, path := range productionFilesIn(t, kubernetesLibraryImporter) {
		scanned++
		for _, imported := range parseFile(t, path).Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if !strings.HasPrefix(importPath, "k8s.io/") &&
				!strings.HasPrefix(importPath, "sigs.k8s.io/") {
				continue
			}
			seen[importPath] = true
			if !kubernetesClientAllowlist[importPath] {
				t.Errorf("%s imports %s, which is not on ADR 0094 §2.1's allowlist.\n\n"+
					"The refused set is the point: the full Clientset, the dynamic client, "+
					"the discovery client, informers, listers, caches, watches and every "+
					"auth plugin. Adding an eleventh path is a decision with its own "+
					"record.", relative(t, path), importPath)
			}
		}
	}

	if scanned == 0 {
		t.Fatalf("no production source was found in %s; this guard would pass vacuously",
			kubernetesLibraryImporter)
	}
	if len(seen) == 0 {
		t.Fatal("no Kubernetes import was found; this guard would pass vacuously")
	}
}

// TestTheKubernetesClientReachesNoOtherSvcdoctorLayer.
//
// It holds a credential and a live control-plane client, so the layers it must
// not reach are the ones that would let either travel: diagnosis, the renderer,
// the fleet scheduler, the composition root, and every other adapter.
func TestTheKubernetesClientReachesNoOtherSvcdoctorLayer(t *testing.T) {
	forbidden := map[string]string{
		"internal/diagnosis": "an adapter produces evidence; interpreting it is diagnosis work",
		"internal/render":    "an adapter does not render",
		"internal/app":       "an adapter is composed, and does not reach back into the root",
		"internal/cli":       "an adapter is not the command boundary",
		"internal/fleet":     "an adapter knows nothing about multi-target scheduling",
		// The four transport probes, and not internal/probe itself: that package is
		// where ADR 0019 put the evidence-identifier encoding, precisely so two
		// producers cannot disagree about escaping, and every adapter borrows the
		// rule rather than copying it. What a Kubernetes adapter must not reach is
		// a probe that dials, because its transport belongs to the client library.
		"internal/probe/dns":        "the Kubernetes transport belongs to the client library",
		"internal/probe/tcp":        "the Kubernetes transport belongs to the client library",
		"internal/probe/tls":        "the Kubernetes transport belongs to the client library",
		"internal/probe/transport":  "the Kubernetes transport belongs to the client library",
		"internal/adapter/kafka":    "one service adapter never reaches another",
		"internal/adapter/postgres": "one service adapter never reaches another",
		"internal/adapter/redis":    "one service adapter never reaches another",
		"internal/adapter/rabbitmq": "one service adapter never reaches another",
	}

	scanned := 0
	for _, pkg := range []string{
		kubernetesLibraryImporter, "internal/adapter/kubernetes", "internal/service/kubernetes",
	} {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			for _, imported := range parseFile(t, path).Imports {
				importPath := strings.Trim(imported.Path.Value, `"`)
				for prefix, why := range forbidden {
					full := "github.com/hakanaltindag/svcdoctor/" + prefix
					if importPath == full || strings.HasPrefix(importPath, full+"/") {
						t.Errorf("%s imports %s: %s", relative(t, path), importPath, why)
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no Kubernetes source was scanned; this guard would pass vacuously")
	}
}

// TestTheKubernetesVocabularyIsALeaf.
//
// It exists so that diagnosis and the renderer can name Kubernetes steps and
// attributes without reaching the package that produces them. A vocabulary that
// grew a dependency would become the shared service layer ADR 0034 declined to
// create.
func TestTheKubernetesVocabularyIsALeaf(t *testing.T) {
	const vocabulary = "internal/service/kubernetes"
	scanned := 0
	for _, path := range productionFilesIn(t, vocabulary) {
		scanned++
		for _, imported := range parseFile(t, path).Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if importPath == "github.com/hakanaltindag/svcdoctor/internal/domain" {
				continue
			}
			if !strings.Contains(importPath, ".") {
				t.Errorf("%s imports the standard library package %s; a vocabulary is "+
					"constants over internal/domain and nothing else",
					relative(t, path), importPath)
				continue
			}
			t.Errorf("%s imports %s; a vocabulary imports internal/domain and nothing else",
				relative(t, path), importPath)
		}
	}
	if scanned == 0 {
		t.Fatalf("no source was found in %s; this guard would pass vacuously", vocabulary)
	}
}

// TestNoKubernetesSpecialCaseExistsInAnyGenericPackage is ADR 0071 section 6.3,
// measured for a fifth service.
//
// The registry exists precisely so that adding a service needs no edit to the
// runner, the decoder, the aggregate report, the renderer or the exit mapping. A
// string literal naming Kubernetes in one of those is the first line of the
// central branching the extensibility rule forbids.
func TestNoKubernetesSpecialCaseExistsInAnyGenericPackage(t *testing.T) {
	scanned := 0
	for _, pkg := range fleetCorePackages {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			for _, literal := range stringLiterals(parseFile(t, path)) {
				if strings.EqualFold(literal, "kubernetes") || strings.EqualFold(literal, "k8s") {
					t.Errorf("%s contains the string literal %q.\n\n"+
						"A fifth service is registered, not branched on.",
						relative(t, path), literal)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no core source was scanned; this guard would pass vacuously")
	}
}

// TestTheGenericCoreImportsNoKubernetesPackage states the same boundary as an
// import rule rather than a literal one.
//
// The two catch different mistakes: a literal is how a branch begins, and an
// import is how a type leaks. `internal/domain` is the one that matters most —
// a Kubernetes type reachable from the canonical report would put a control-plane
// API into the schema every consumer parses.
func TestTheGenericCoreImportsNoKubernetesPackage(t *testing.T) {
	core := []string{
		"internal/domain", "internal/diagnosis", "internal/render/json",
		"internal/render/terminal", "internal/probe", "internal/security",
		"internal/security/redaction", "internal/cli", "internal/fleet/config",
		"internal/fleet/run", "internal/fleet/secret",
	}

	scanned := 0
	for _, pkg := range core {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, marker := range []string{"k8s.io/", "sigs.k8s.io/"} {
				if strings.Contains(string(source), marker) {
					t.Errorf("%s mentions %s; the generic core consumes svcdoctor's own "+
						"normalized values and never a Kubernetes type",
						relative(t, path), marker)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no core source was scanned; this guard would pass vacuously")
	}
}

// TestTheKubernetesAdapterNeverProducesAFinding is Phase 12.1B's own boundary.
//
// # Why it is a security test rather than an architecture one
//
// The four Kubernetes finding codes are claims about somebody's cluster, and each
// carries a claim ceiling ADR 0094 section 2.7 froze — F4 may never say a Service
// is unreachable, F2 may never say the objects are absent. A finding produced
// before the phase that argued those ceilings would carry none of them.
//
// Phase 12.1C removes this guard's premise deliberately, by wiring the rules. It
// is written to fail loudly at that point rather than to be forgotten.
func TestTheKubernetesAdapterNeverProducesAFinding(t *testing.T) {
	forbidden := []string{
		"NewFinding", "FindingCode", "SeverityError", "SeverityWarn",
		"ConfidenceHigh", "domain.Recommendation",
	}

	scanned := 0
	for _, pkg := range []string{
		kubernetesLibraryImporter, "internal/adapter/kubernetes", "internal/service/kubernetes",
	} {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, marker := range forbidden {
				if strings.Contains(string(source), marker) {
					t.Errorf("%s mentions %s.\n\n"+
						"Phase 12.1B is acquisition: it produces evidence and concludes "+
						"nothing. The four Kubernetes findings, their severities and their "+
						"claim ceilings are Phase 12.1C's, and a finding produced here "+
						"would carry none of them.", relative(t, path), marker)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no Kubernetes source was scanned; this guard would pass vacuously")
	}
}

// kubernetesFindingCodes is the whole first-scope Kubernetes claim budget.
//
// They are named exactly rather than matched by prefix, because
// `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` are the two variables
// the kubelet injects and the in-cluster path legitimately reads them. A prefix
// match finds those, and weakening the guard to tolerate them would weaken it
// against the thing it is for.
var kubernetesFindingCodes = map[string]string{
	"KUBERNETES_SERVICE_NOT_FOUND":         "internal/diagnosis/kubernetes/acquisition.go",
	"KUBERNETES_API_ACCESS_DENIED":         "internal/diagnosis/kubernetes/acquisition.go",
	"KUBERNETES_SERVICE_SELECTS_NO_PODS":   "internal/diagnosis/kubernetes/backends.go",
	"KUBERNETES_SERVICE_NO_READY_ENDPOINT": "internal/diagnosis/kubernetes/backends.go",
}

// TestTheKubernetesFindingCodesAreExactlyTheFourFrozenOnes pins the budget from
// both directions.
//
// # It replaces a guard rather than deleting one
//
// Until Phase 12.1C this test was `TestNoKubernetesFindingCodeExistsYet`, and it
// asserted that none of the four existed anywhere in the tree. Phase 12.1C
// removes that premise deliberately, by wiring the rules — so the assertion is
// turned around rather than dropped, exactly as
// `test/security/rabbitmq_contract_freeze_test.go` was turned around at Phase
// 8.2. A guard that only ever said "not yet" is worth nothing the day it comes
// true.
//
// What it now states is the half that stays permanent: **these four and no
// fifth**, each declared in the diagnosis package that owns it and nowhere else.
// ADR 0094 section 7's reopen condition for a fifth is a bounded operator
// question no admitted finding answers, whose discriminating value comes from an
// API-contract enumeration rather than from a message — which is a decision with
// its own record, not an edit to this map.
func TestTheKubernetesFindingCodesAreExactlyTheFourFrozenOnes(t *testing.T) {
	scanned := 0
	found := map[string][]string{}

	for _, pkg := range allProductionPackages(t) {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			for _, literal := range stringLiterals(parseFile(t, path)) {
				// A finding code is one screaming-snake-case token and nothing
				// else. Matching the shape rather than the prefix alone is what
				// keeps an error message that *opens* with one of these names
				// from being read as a declaration of it — the in-cluster path
				// has two such sentences.
				if !isKubernetesCodeShaped(literal) {
					continue
				}
				// The two kubelet-injected variables are not finding codes and
				// the in-cluster path legitimately names them.
				if literal == "KUBERNETES_SERVICE_HOST" ||
					literal == "KUBERNETES_SERVICE_PORT" {
					continue
				}
				found[literal] = append(found[literal], relative(t, path))
			}
		}
	}

	if scanned == 0 {
		t.Fatal("no source was scanned; this guard would pass vacuously")
	}
	if len(found) == 0 {
		t.Fatal("no KUBERNETES_ literal was found at all; the four finding codes are " +
			"Phase 12.1C's whole behavioural change and this guard would pass vacuously")
	}

	for code, paths := range found {
		want, frozen := kubernetesFindingCodes[code]
		if !frozen {
			t.Errorf("%s is declared in %v and is not one of the four codes ADR 0094 "+
				"section 2.7 froze.\n\n"+
				"The budget is four. A fifth needs a bounded operator question no admitted "+
				"finding answers, whose discriminating value comes from an API-contract "+
				"enumeration rather than from a message (ADR 0094 section 7).",
				code, paths)
			continue
		}
		for _, path := range paths {
			if path != want {
				t.Errorf("%s is named in %s; it belongs in %s, where the rule that "+
					"produces it lives.\n\n"+
					"A finding code named outside its own diagnosis package is the first "+
					"sign that something other than a rule is deciding what svcdoctor "+
					"claims.", code, path, want)
			}
		}
	}
	for code := range kubernetesFindingCodes {
		if _, declared := found[code]; !declared {
			t.Errorf("%s is frozen by ADR 0094 section 2.7 and is declared nowhere; "+
				"every one of the four arrives with the rule that produces it", code)
		}
	}
}

// TestNoKubernetesSourceReadsAStatusMessage is ADR 0094 section 2.8, structurally.
//
// # Why a behavioural test cannot state this
//
// The contract is that `Status.Message`, `Status.details.causes[].message` and
// every condition or status message are *"never read, never matched, never parsed
// and never interpolated"*. A behavioural test can only show that a hostile
// message did not reach the output of a particular run — and it cannot fail at
// all once the values are enums, because an enum has no room to carry a string.
//
// That is not a hypothetical gap. Phase 12.1B planted a classifier that branched
// on the message and it **survived** every behavioural test, because the branch
// it added was unreachable for the inputs those tests supplied. The property is
// about the source, so this reads the source.
//
// Reading the field at all is the violation. Once a message is in a local
// variable it is one interpolation away from an error, a log line or a report,
// and the reason this contract is structural rather than an escaping exercise is
// that escaping is something a later edit forgets.
func TestNoKubernetesSourceReadsAStatusMessage(t *testing.T) {
	// The field names that carry peer-supplied prose. `Reason` and `Code` are
	// deliberately absent: those are the API's own enumerations and are exactly
	// what svcdoctor classifies from.
	//
	// Matched on the **syntax tree** rather than on the file's text, because the
	// text form catches this guard's own subject: apierror.go's doc comment says
	// "Status.Message ... are never read", and a naive scan flagged the sentence
	// that states the rule. A selector expression is the thing that reads a
	// field, and a comment is not one.
	forbidden := map[string]string{
		"Message": "a Kubernetes status or condition message",
		"Details": "a Status details block, whose causes carry messages",
		"Causes":  "a Status cause list, whose entries carry messages",
	}

	scanned := 0
	for _, pkg := range []string{
		kubernetesLibraryImporter, "internal/adapter/kubernetes", "internal/service/kubernetes",
	} {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
				selector, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				why, forbiddenField := forbidden[selector.Sel.Name]
				if !forbiddenField {
					return true
				}
				t.Errorf("%s reads .%s — %s.\n\n"+
					"A Kubernetes status message is text whoever controls the cluster — or "+
					"whoever can answer as it — chooses. It is never read, matched, parsed "+
					"or interpolated, which keeps ANSI, CRLF, token-shaped values and "+
					"filesystem paths out structurally rather than by escaping "+
					"(ADR 0094 §2.8). Classify from the HTTP status and "+
					"metav1.StatusReason instead.", relative(t, path), selector.Sel.Name, why)
				return true
			})
		}
	}
	if scanned == 0 {
		t.Fatal("no Kubernetes source was scanned; this guard would pass vacuously")
	}
}

// isKubernetesCodeShaped reports whether a literal has a finding code's shape.
//
// `KUBERNETES_` followed by upper-case letters, digits and underscores, to the
// end. A space, a lower-case letter or any punctuation makes it prose.
func isKubernetesCodeShaped(literal string) bool {
	if !strings.HasPrefix(literal, "KUBERNETES_") {
		return false
	}
	for i := 0; i < len(literal); i++ {
		c := literal[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

// --- Phase 12.1C: the diagnosis boundary -------------------------------------

// kubernetesRulePackage is the only package that may hold a Kubernetes rule.
const kubernetesRulePackage = "internal/diagnosis/kubernetes"

// TestTheKubernetesRulesImportNothingBelowDiagnosis is K-P12.
//
// # Why an allowlist rather than a denylist
//
// A rule reads a frozen graph and nothing else. Listing what it may import means
// an import nobody anticipated is refused by default, where a denylist refuses
// only what somebody thought of — and the imports that would matter most here
// are precisely the ones a future author would reach for without thinking: the
// adapter, to re-read an object; client-go, to ask the API server one more
// question; internal/security, to look at a credential.
//
// `depguard`'s `diagnosis-is-pure` list states the same property at lint time.
// This is the independent statement of it, and it catches the case a lint
// configuration cannot: an edit to `.golangci.yml` itself.
func TestTheKubernetesRulesImportNothingBelowDiagnosis(t *testing.T) {
	permitted := map[string]bool{
		"fmt": true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis":          true,
		"github.com/hakanaltindag/svcdoctor/internal/domain":             true,
		"github.com/hakanaltindag/svcdoctor/internal/service/kubernetes": true,
	}

	scanned := 0
	for _, path := range productionFilesIn(t, kubernetesRulePackage) {
		scanned++
		for _, imported := range parseFile(t, path).Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if !permitted[importPath] {
				t.Errorf("%s imports %s, which is not on the allowlist.\n\n"+
					"Diagnosis consumes normalized evidence. An adapter import could "+
					"re-read a Kubernetes object, a k8s.io import could open a socket, an "+
					"internal/security import could reach a credential, and net or os "+
					"could perform I/O — none of which a rule may do (ADR 0094 §2.12).",
					relative(t, path), importPath)
			}
		}
	}
	if scanned == 0 {
		t.Fatalf("no production source was found in %s; this guard would pass vacuously",
			kubernetesRulePackage)
	}
}

// TestNoKubernetesRuleActivatesAnEvidenceRelation is K-P11.
//
// ADR 0087's outcome is **DEFER**: `EvidenceBasis`'s `Contradict`, `Miss` and
// `Block` relations have zero producers, and two guards in `AdmitConfidence` are
// vacuous in a way that is safe only while `AuthorityCompleteContrast` has none
// either — so the two must be armed in one change-set, which Phase 12.1C is not.
//
// `Finding.EvidenceRefs` is deliberately **not** a relation producer, and the
// distinction is the whole point: it means "evidence backing this finding",
// never a SUPPORT edge (ADR 0087 §2.1, docs/FINDINGS.md §3.1 rule 20).
func TestNoKubernetesRuleActivatesAnEvidenceRelation(t *testing.T) {
	forbidden := map[string]string{
		"BasisBuilder":              "the basis machinery has no producer and arming one is a decision",
		"EvidenceBasis":             "the same",
		"AuthorityCompleteContrast": "ADR 0094 §10.6 chose AuthorityDirect for all four; complete-contrast would arm a vacuous AdmitConfidence guard",
		"AdmitConfidence":           "ADR 0094 §10.6 records that routing through the ladder is not output-neutral, and the four rules set the literal as 21 of the other 22 do",
	}

	scanned := 0
	for _, path := range productionFilesIn(t, kubernetesRulePackage) {
		scanned++
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for marker, why := range forbidden {
			if strings.Contains(string(source), marker) {
				t.Errorf("%s names %s: %s", relative(t, path), marker, why)
			}
		}
	}
	if scanned == 0 {
		t.Fatalf("no production source was found in %s; this guard would pass vacuously",
			kubernetesRulePackage)
	}
}

// TestTheKubernetesDiagnosisReachesNoCredential.
//
// A rule has nothing to reveal — `RuleContext` carries a graph, a vantage and a
// boolean, and there is no credential in any of them — so this states the
// property at the source, where a future author would have to write the name
// before the type could stop them.
//
// The global counts are pinned separately and stay where Phase 12.1B left them:
// five `Reveal` sites and five `SecretFor` sites, one per service.
func TestTheKubernetesDiagnosisReachesNoCredential(t *testing.T) {
	scanned := 0
	for _, path := range productionFilesIn(t, kubernetesRulePackage) {
		scanned++
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, marker := range []string{
			"Reveal", "SecretFor", "security.", "Credential", "Secret",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("%s names %s; diagnosis holds no credential and needs none",
					relative(t, path), marker)
			}
		}
	}
	if scanned == 0 {
		t.Fatalf("no production source was found in %s; this guard would pass vacuously",
			kubernetesRulePackage)
	}
}

// TestTheKubernetesCompositionRootWiresExactlyThreeRules.
//
// ADR 0094 §2.10 froze the production rule count at 22 → 24: **one acquisition
// rule and one publication rule**, plus the generic failure boundary every
// composition root already wires.
//
// It also pins the two things that are deliberately *absent*. No transport rule
// is wired, because a Kubernetes run measures no DNS, TCP or TLS stage of its
// own — transport belongs to the client library — and a rule whose steps cannot
// appear would be silent by construction rather than by measurement. And no
// fourth Kubernetes rule exists.
func TestTheKubernetesCompositionRootWiresExactlyThreeRules(t *testing.T) {
	// Read from the syntax tree rather than from the file's text. The chained
	// builder puts `Add(` at the start of a line, so a text scan for `.Add("`
	// finds nothing — and a text scan for `transport/dns` finds the doc comment
	// that explains why no transport rule is wired. A call expression is the
	// thing that wires a rule, and prose is not one.
	path := filepath.Join(repositoryRoot(t), "internal/app/kubernetes.go")
	file := parseFile(t, path)

	var wired []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Add" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		wired = append(wired, strings.Trim(literal.Value, `"`))
		return true
	})

	// The walk visits a method chain outermost-first, so the collected order is
	// the reverse of the written one. Both are sorted before comparing, because
	// wiring order does not reach the output at all: Phase 10.2A made RuleID
	// unable to influence any merged field, and permuting the rule set is a
	// permanent property test (ADR 0081 section 2.6a). What is asserted here is
	// the *set*.
	slices.Sort(wired)
	want := []string{
		"diag/failure-boundary",
		"kubernetes/acquisition",
		"kubernetes/backends",
	}
	if len(wired) != len(want) {
		t.Fatalf("the Kubernetes composition root wires %v, want exactly %v.\n\n"+
			"ADR 0094 section 2.10 froze 22 -> 24: one acquisition rule and one "+
			"publication rule, beside the generic boundary. A transport rule is "+
			"deliberately absent because a Kubernetes run measures no transport stage "+
			"of its own — transport belongs to the client library — so a rule whose "+
			"steps cannot appear would be silent by construction rather than by "+
			"measurement.", wired, want)
	}
	for i, id := range want {
		if wired[i] != id {
			t.Errorf("the wired set holds %q where %q was expected; the set is %v",
				wired[i], id, wired)
		}
	}
}
