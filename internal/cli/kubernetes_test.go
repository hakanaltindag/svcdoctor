package cli

import (
	"bytes"
	"context"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// The Phase 12.1C.2 leaf-command contract, tested from outside the parser.
//
// # What this file is for, and what it deliberately is not
//
// `PHASE121C1…§5` froze ten flags and `§10` froze a refused surface. Both are
// **public released surface** in this repository — a leaf flag set is what an
// operator writes into a runbook — so both are pinned here mechanically rather
// than described.
//
// Nothing here reaches a network. The parse path calls
// `app.InspectKubernetesTarget`, which performs no network operation by
// construction, so every invalid-configuration row below is decided with zero
// API requests as a *property of the architecture* rather than of the fixture.
// The hermetic end-to-end proof — that the same rows really do reach a running
// API server zero times — is `test/fleet/kubernetesleaf_test.go`, which lives
// there because `depguard` denies `net/http` in this package.

// --- the public flag surface ------------------------------------------------

// kubernetesFlags is the exact frozen public surface of `diagnose kubernetes`.
//
// **Exact in both directions, and written out rather than read from the
// production declaration.** A guard that derived the expected set from the code
// it guards would pass for any set at all; this one fails if a flag disappears,
// is renamed, or an eleventh appears.
//
// `PHASE121C1…§5` classifies each: five DERIVED from the five frozen target
// fields, `--token-file` EXPLICITLY_FROZEN by `PHASE121A…§6.1` mode A,
// `--token-stdin` DERIVED from ADR 0049's file-or-pipe pair, and
// `--timeout`/`--output`/`--shareable` SHARED unchanged from the four commands
// that came before.
var kubernetesFlags = map[string]bool{
	"kubeconfig": true, "context": true, "in-cluster": true,
	"namespace": true, "service-name": true,
	"token-file": true, "token-stdin": true,
	"timeout": true, "output": true, "shareable": true,
}

// kubernetesFlagCount is stated separately from the map so that a duplicated key
// — which a map literal silently accepts at neither compile nor run time — still
// fails the count.
const kubernetesFlagCount = 10

// kubernetesForbiddenFlags are the flags that must never exist.
//
// Every one is something a reasonable person would add, and each would break a
// frozen decision. They are the `PHASE121C1…§10` table, driven rather than read:
// an endpoint flag would contradict the derived API server (ADR 0094 §2.4); a
// certificate flag would be a second Kubernetes configuration model; a literal
// token would put a secret in argv (ADR 0049 §5); a TLS flag would be a second
// answer to a question the kubeconfig already answers; `--step-timeout` and any
// budget flag would be inert or, worse, able to silence a finding by making an
// enumeration incomplete; and every scope flag would widen MVP-D.
var kubernetesForbiddenFlags = []string{
	// The endpoint the target does not name.
	"host", "port", "server", "api-server", "url", "endpoint",
	// Identity svcdoctor does not take from the command line.
	"user", "username", "password", "password-file", "password-stdin",
	"token", "client-cert", "client-key", "cert-file", "key-file",
	// Trust and verification, which the kubeconfig owns.
	"tls", "tls-ca-file", "tls-server-name", "tls-insecure",
	"insecure", "insecure-skip-tls-verify", "ca-file",
	// Refused authority constructs.
	"impersonate", "as", "as-group", "proxy-url", "exec", "auth-provider",
	"allow-exec-auth", "anonymous",
	// Scope, which MVP-D fixes at one Service.
	"all-namespaces", "namespace-pattern", "service-pattern", "selector",
	"pod", "deployment", "workload", "node",
	// Reads that do not exist.
	"events", "logs", "metrics", "network-policy", "probe-endpoints",
	"ingress", "gateway",
	// Budgets and per-step bounds, which stay constants.
	"step-timeout", "page-size", "limit", "max-pages", "max-pods",
	"max-slices", "max-endpoints", "max-requests",
	// The fleet's own surface, which a leaf never gains.
	"config", "config-file", "target", "targets", "concurrency",
	// Another service's flags.
	"database", "sasl-mechanism", "vhost",
}

// TestTheKubernetesFlagSurfaceIsExact reads the flags the parser actually
// registers rather than the help text, so a flag that exists but is
// undocumented still fails.
func TestTheKubernetesFlagSurfaceIsExact(t *testing.T) {
	defined := kubernetesDefinedFlags(t)

	if len(defined) == 0 {
		t.Fatal("no flags were parsed out of parseKubernetes; this guard would pass vacuously")
	}
	if len(defined) != kubernetesFlagCount {
		t.Errorf("`diagnose kubernetes` defines %d flags, want exactly %d.\n\n"+
			"PHASE121C1 froze the surface at ten and named what is absent and why. "+
			"An eleventh is a decision with its own record.", len(defined), kubernetesFlagCount)
	}
	if len(kubernetesFlags) != kubernetesFlagCount {
		t.Fatalf("kubernetesFlags holds %d names, want %d; a duplicated key would hide here",
			len(kubernetesFlags), kubernetesFlagCount)
	}

	for name := range kubernetesFlags {
		if !defined[name] {
			t.Errorf("--%s is frozen in the Kubernetes surface and the command does not "+
				"define it", name)
		}
	}
	for name := range defined {
		if !kubernetesFlags[name] {
			t.Errorf("`diagnose kubernetes` defines --%s, which the frozen surface does "+
				"not authorize.\n\nAdd it to kubernetesFlags deliberately, with the record "+
				"that authorizes it, or remove it.", name)
		}
	}
}

// TestTheKubernetesCommandRejectsForbiddenFlags is the behavioural half.
//
// The surface test reads the source; this drives the real parser, so a flag that
// somehow became accepted at runtime fails here even if the source scan missed
// it. The seam asserts the stronger property too: **no run starts.**
func TestTheKubernetesCommandRejectsForbiddenFlags(t *testing.T) {
	for _, name := range kubernetesForbiddenFlags {
		t.Run(name, func(t *testing.T) {
			a := kubernetesTestApp(t, "")
			code := a.Run(context.Background(), []string{
				"diagnose", "kubernetes",
				"--namespace", "n", "--service-name", "s", "--in-cluster",
				"--" + name, "x",
			})
			if code != ExitUsage {
				t.Errorf("--%s exited %d, want %d (usage)", name, code, ExitUsage)
			}
		})
	}
}

// TestTheKubernetesForbiddenListAndSurfaceAreDisjoint proves the two lists are
// live rather than agreeing by being empty.
func TestTheKubernetesForbiddenListAndSurfaceAreDisjoint(t *testing.T) {
	if len(kubernetesForbiddenFlags) == 0 {
		t.Fatal("the forbidden list is empty")
	}
	for _, forbidden := range kubernetesForbiddenFlags {
		if kubernetesFlags[forbidden] {
			t.Errorf("%q appears in both the frozen surface and the forbidden list", forbidden)
		}
	}
	// And the four flags every other service carries really are refused here,
	// so the list is not merely a set of names nobody would type.
	for _, name := range []string{"host", "step-timeout", "password-file", "tls-insecure"} {
		found := false
		for _, forbidden := range kubernetesForbiddenFlags {
			if forbidden == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not in the forbidden list; it is a flag every other leaf "+
				"command defines, so its absence here is the thing most likely to be "+
				"added back by habit", name)
		}
	}
}

// --- registration -----------------------------------------------------------

// TestTheKubernetesCommandIsRoutedUnderDiagnose.
//
// ADR 0041's shape: `svcdoctor diagnose kubernetes`, one case in the existing
// switch. `svcdoctor kubernetes` and `svcdoctor diagnose k8s` are refused, and
// no alias exists, because a second spelling is a second public surface.
func TestTheKubernetesCommandIsRoutedUnderDiagnose(t *testing.T) {
	t.Run("routed", func(t *testing.T) {
		a := kubernetesTestApp(t, "")
		var stderr bytes.Buffer
		a.Stderr = &stderr
		// A legal route reaching a target error, which proves the case ran: an
		// unrouted service produces "unknown service" instead.
		a.Run(context.Background(), []string{"diagnose", "kubernetes"})
		if strings.Contains(stderr.String(), "unknown service") {
			t.Errorf("`diagnose kubernetes` was not routed: %s", stderr.String())
		}
	})

	// **The reason is asserted, not only the code.** A spelling that routed to
	// the Kubernetes command would also exit 2 — its target flags are missing —
	// so a test reading the code alone would pass for an alias that exists. What
	// distinguishes them is that an unrouted service is reported as one.
	for _, tc := range []struct {
		args   []string
		reason string
	}{
		{[]string{"diagnose", "k8s"}, "unknown service"},
		{[]string{"diagnose", "kube"}, "unknown service"},
		{[]string{"diagnose", "Kubernetes"}, "unknown service"},
		{[]string{"kubernetes", "--namespace", "n"}, "unknown command"},
		{[]string{"k8s"}, "unknown command"},
		{[]string{"inspect", "kubernetes"}, "unknown command"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			a := kubernetesTestApp(t, "")
			var stderr bytes.Buffer
			a.Stderr = &stderr

			if code := a.Run(context.Background(), tc.args); code != ExitUsage {
				t.Errorf("`svcdoctor %s` exited %d, want %d; only "+
					"`diagnose kubernetes` exists and there is no alias",
					strings.Join(tc.args, " "), code, ExitUsage)
			}
			if !strings.Contains(stderr.String(), tc.reason) {
				t.Errorf("`svcdoctor %s` was refused, but not as %q — so it may have "+
					"been routed to the Kubernetes command and refused for a target "+
					"reason instead.\ngot: %s",
					strings.Join(tc.args, " "), tc.reason, stderr.String())
			}
		})
	}
}

// TestTheKubernetesTokenFileMessagesNameTheKubernetesFlag closes the other half
// of the parameterization.
//
// `TestTheCredentialSourceHelperNamesTheCallersFlags` covers the exclusivity
// message. The *file* messages are a separate branch of the same helper, and a
// mutation restoring `--password-file` there survived every other guard in this
// file — the Kubernetes command would have told an operator to fix a flag it
// does not define.
func TestTheKubernetesTokenFileMessagesNameTheKubernetesFlag(t *testing.T) {
	directory := t.TempDir()

	tests := map[string]string{
		"a directory":    directory,
		"a missing file": filepath.Join(directory, "absent"),
	}

	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			a := kubernetesTestApp(t, "")
			var stderr bytes.Buffer
			a.Stderr = &stderr

			code := a.Run(context.Background(), []string{
				"diagnose", "kubernetes",
				"--kubeconfig", kubernetesTokenlessKubeconfig(t), "--context", "prod",
				"--namespace", "n", "--service-name", "s",
				"--token-file", path,
			})

			if code != ExitUsage {
				t.Errorf("exited %d, want %d", code, ExitUsage)
			}
			if !strings.Contains(stderr.String(), "--token-file") {
				t.Errorf("the message does not name --token-file, so it names a flag "+
					"this command does not define.\ngot: %s", stderr.String())
			}
			if strings.Contains(stderr.String(), "--password-file") {
				t.Errorf("the message names --password-file, which `diagnose kubernetes` "+
					"refuses as an unknown flag.\ngot: %s", stderr.String())
			}
			if !strings.Contains(stderr.String(), path) {
				t.Errorf("the message does not name the path, so an operator cannot fix "+
					"it: %s", stderr.String())
			}
		})
	}
}

// --- defaults ---------------------------------------------------------------

// TestTheKubernetesDefaultsAreTheFrozenOnes.
//
// The three defaults are read from a parsed command rather than from the flag
// declarations, so a default changed anywhere on the path fails.
func TestTheKubernetesDefaultsAreTheFrozenOnes(t *testing.T) {
	a := kubernetesTestApp(t, "")
	command, err := a.parseKubernetes([]string{
		"--in-cluster", "--namespace", "payments", "--service-name", "checkout",
	})
	if err != nil {
		t.Fatalf("a minimal in-cluster invocation was refused: %v", err)
	}

	if command.timeout != 30*time.Second {
		t.Errorf("--timeout defaults to %s, want 30s", command.timeout)
	}
	if command.output != "text" {
		t.Errorf("--output defaults to %q, want \"text\"", command.output)
	}
	if command.shareable {
		t.Error("--shareable defaults to true; the local report is the default and a " +
			"redacted one is asked for")
	}
	if !command.params.Credential.IsZero() {
		t.Error("an invocation naming no credential source produced a credential")
	}
}

// TestTheKubernetesAcquisitionBudgetsAreNotReachable.
//
// `PHASE121C1…§9.3`'s decisive reason, stated as a test: a budget is a
// *completeness* input, and both universal findings require a complete
// enumeration — so a flag able to lower one could silence a finding. The command
// leaves Budgets zero, which the adapter reads as the frozen defaults, exactly
// as the fleet runner does.
func TestTheKubernetesAcquisitionBudgetsAreNotReachable(t *testing.T) {
	a := kubernetesTestApp(t, "")
	command, err := a.parseKubernetes([]string{
		"--in-cluster", "--namespace", "payments", "--service-name", "checkout",
	})
	if err != nil {
		t.Fatalf("a minimal in-cluster invocation was refused: %v", err)
	}
	if command.params.Budgets != (app.KubernetesParams{}).Budgets {
		t.Errorf("the command set an acquisition budget: %+v.\n\n"+
			"Leaving it zero is what makes the leaf and the fleet ask for the same "+
			"three reads under the same five ceilings.", command.params.Budgets)
	}
}

// --- target validation is delegated, not duplicated -------------------------

// TestTheKubernetesTargetRulesAreTheAdapters.
//
// Every row here is a target-shape or authority defect, and every one exits 2.
// The **message** is asserted to be the adapter's own, which is the property
// that matters: if the CLI had restated any of these rules, the wording would be
// this package's and the fleet decoder could answer differently for the same
// file. `PHASE121C1…§6` forbids exactly that.
func TestTheKubernetesTargetRulesAreTheAdapters(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains string
	}{
		{
			name:     "neither authority",
			args:     []string{"--namespace", "n", "--service-name", "s"},
			contains: "kubeconfig path or in-cluster mode is required",
		},
		{
			name: "both authorities",
			args: []string{"--in-cluster", "--kubeconfig", "/nonexistent",
				"--namespace", "n", "--service-name", "s"},
			contains: "mutually exclusive",
		},
		{
			name: "context in-cluster",
			args: []string{"--in-cluster", "--context", "prod",
				"--namespace", "n", "--service-name", "s"},
			contains: "no meaning in-cluster",
		},
		{
			name: "kubeconfig without context",
			args: []string{"--kubeconfig", "/nonexistent",
				"--namespace", "n", "--service-name", "s"},
			contains: "current-context is never used",
		},
		{
			name:     "no namespace",
			args:     []string{"--in-cluster", "--service-name", "s"},
			contains: "namespace is required and is never defaulted",
		},
		{
			name:     "no service name",
			args:     []string{"--in-cluster", "--namespace", "n"},
			contains: "service name is required and is never defaulted",
		},
		{
			name:     "namespace with a separator",
			args:     []string{"--in-cluster", "--namespace", "a/b", "--service-name", "s"},
			contains: `which no Kubernetes object name may hold`,
		},
		{
			name:     "service name with a control character",
			args:     []string{"--in-cluster", "--namespace", "n", "--service-name", "a\tb"},
			contains: "space or a control character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := kubernetesTestApp(t, "")
			var stderr bytes.Buffer
			a.Stderr = &stderr

			code := a.Run(context.Background(),
				append([]string{"diagnose", "kubernetes"}, tt.args...))

			if code != ExitUsage {
				t.Errorf("exited %d, want %d (usage); a target defect is something the "+
					"operator wrote, not a svcdoctor failure", code, ExitUsage)
			}
			if !strings.Contains(stderr.String(), tt.contains) {
				t.Errorf("stderr does not carry the adapter's own wording %q.\n\n"+
					"The CLI must not restate a target rule; it asks "+
					"app.InspectKubernetesTarget and reports the answer.\ngot: %s",
					tt.contains, stderr.String())
			}
		})
	}
}

// --- the credential sources -------------------------------------------------

// TestTheKubernetesTokenSourcesAreExclusiveAndNamed.
//
// ADR 0049 §2 refuses ambiguity rather than resolving it, and the message names
// the two flags **this** command exposes — which is the whole point of the
// generic helper carrying the pair as data.
func TestTheKubernetesTokenSourcesAreExclusiveAndNamed(t *testing.T) {
	a := kubernetesTestApp(t, "")
	var stderr bytes.Buffer
	a.Stderr = &stderr

	code := a.Run(context.Background(), []string{
		"diagnose", "kubernetes", "--in-cluster",
		"--namespace", "n", "--service-name", "s",
		"--token-file", "/nonexistent", "--token-stdin",
	})

	if code != ExitUsage {
		t.Errorf("two token sources exited %d, want %d", code, ExitUsage)
	}
	if want := "--token-file and --token-stdin are mutually exclusive"; !strings.Contains(
		stderr.String(), want) {
		t.Errorf("the refusal does not name this command's own flags.\nwant %q\ngot  %s",
			want, stderr.String())
	}
	if strings.Contains(stderr.String(), "password") {
		t.Errorf("the Kubernetes refusal names a password; the credential is a bearer "+
			"token and --password-file names the one mode ADR 0094 §2.3 refuses.\ngot: %s",
			stderr.String())
	}
}

// TestATokenSourceIsRefusedInClusterMode.
//
// `client.Inspect` owns the rule and the CLI does not restate it: in-cluster
// authenticates as the pod's ServiceAccount, so a target credential would be a
// second identity nobody asked for.
func TestATokenSourceIsRefusedInClusterMode(t *testing.T) {
	for _, source := range [][]string{
		{"--token-file", kubernetesTokenFile(t, "a-token")},
		{"--token-stdin"},
	} {
		t.Run(source[0], func(t *testing.T) {
			a := kubernetesTestApp(t, "a-token")
			var stderr bytes.Buffer
			a.Stderr = &stderr

			code := a.Run(context.Background(), append([]string{
				"diagnose", "kubernetes", "--in-cluster",
				"--namespace", "n", "--service-name", "s",
			}, source...))

			if code != ExitUsage {
				t.Errorf("%s with --in-cluster exited %d, want %d", source[0], code, ExitUsage)
			}
			if !strings.Contains(stderr.String(), "second identity nobody asked for") {
				t.Errorf("the refusal is not the adapter's: %s", stderr.String())
			}
		})
	}
}

// TestAnEmptyDeclaredTokenSourceIsAUsageError is the one place the Kubernetes
// command deliberately differs from its four siblings, and the difference is
// structural rather than stylistic.
//
// For the other four an empty source means *no credential*, and the run
// continues to a truthful `*_CREDENTIAL_NOT_CONFIGURED` finding at exit 0. Here
// it cannot: `Inspect` was already told a credential is supplied and selected
// the bearer-token mode on that basis, and Kubernetes has **no**
// credential-not-configured finding and cannot gain one, because ADR 0094 §2.7
// freezes the four codes. Continuing would be a fact the report has no way to
// state. `internal/fleet/secret` already refuses the same shape for the same
// mode.
func TestAnEmptyDeclaredTokenSourceIsAUsageError(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		flag  string
	}{
		{"empty file", []string{"--token-file", kubernetesTokenFile(t, "")}, "", "--token-file"},
		{"one newline", []string{"--token-file", kubernetesTokenFile(t, "\n")}, "", "--token-file"},
		{"empty stdin", []string{"--token-stdin"}, "", "--token-stdin"},
		{"stdin newline", []string{"--token-stdin"}, "\n", "--token-stdin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := kubernetesTestApp(t, tt.stdin)
			var stderr bytes.Buffer
			a.Stderr = &stderr

			code := a.Run(context.Background(), append([]string{
				"diagnose", "kubernetes",
				"--kubeconfig", kubernetesTokenlessKubeconfig(t),
				"--context", "prod",
				"--namespace", "n", "--service-name", "s",
			}, tt.args...))

			if code != ExitUsage {
				t.Errorf("an empty %s exited %d, want %d.\n\nIt must never be "+
					"reinterpreted as 'no credential configured': that is a finding "+
					"Kubernetes does not have.\nstderr: %s",
					tt.flag, code, ExitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.flag) {
				t.Errorf("the refusal does not name %s: %s", tt.flag, stderr.String())
			}
			if !strings.Contains(stderr.String(), "holds no bearer token") {
				t.Errorf("the refusal does not say what was wrong: %s", stderr.String())
			}
		})
	}
}

// TestADeclaredTokenBindsToTheDerivedAPIServer.
//
// The credential exists, it is bound, and the endpoint it is bound to is the one
// the kubeconfig's own `server:` names — never a value the operator typed,
// because no flag carries one.
func TestADeclaredTokenBindsToTheDerivedAPIServer(t *testing.T) {
	a := kubernetesTestApp(t, "")
	command, err := a.parseKubernetes([]string{
		"--kubeconfig", kubernetesTokenlessKubeconfig(t),
		"--context", "prod",
		"--namespace", "payments", "--service-name", "checkout",
		"--token-file", kubernetesTokenFile(t, "a-bearer-token"),
	})
	if err != nil {
		t.Fatalf("a token-file invocation was refused: %v", err)
	}

	credential := command.params.Credential
	if credential.IsZero() {
		t.Fatal("a declared token produced no credential")
	}
	if host := credential.Endpoint().Host(); host != "api.example.invalid" {
		t.Errorf("the credential is bound to %q, want the kubeconfig's own server host", host)
	}
	if port := credential.Endpoint().Port(); port != 6443 {
		t.Errorf("the credential is bound to port %d, want the server URL's own", port)
	}
	if identity := credential.Identity(); identity != "" {
		t.Errorf("the credential carries the identity %q; a Kubernetes credential carries "+
			"no username, and the API server decides who the token names", identity)
	}
}

// TestTheKubernetesCommandRefusesAKubeconfigCredentialAmbiguity.
//
// A token beside a kubeconfig user that already carries one declares two
// identities. `resolveKubeconfigMode` refuses rather than preferring, and the
// CLI does not resolve it either.
func TestTheKubernetesCommandRefusesAKubeconfigCredentialAmbiguity(t *testing.T) {
	a := kubernetesTestApp(t, "")
	var stderr bytes.Buffer
	a.Stderr = &stderr

	code := a.Run(context.Background(), []string{
		"diagnose", "kubernetes",
		"--kubeconfig", kubernetesTokenKubeconfig(t),
		"--context", "prod",
		"--namespace", "n", "--service-name", "s",
		"--token-file", kubernetesTokenFile(t, "another-token"),
	})

	if code != ExitUsage {
		t.Errorf("two declared identities exited %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "refuses the ambiguity rather than choosing") {
		t.Errorf("the refusal is not the adapter's: %s", stderr.String())
	}
}

// --- structural boundaries --------------------------------------------------

// TestTheCommandBoundaryImportsNoKubernetesLibrary.
//
// `depguard` states the same rule for every package under `internal/` except the
// one importer, and this restates it for the package a fifth service was most
// likely to breach: the leaf command builds `app.KubernetesTarget` — a type
// alias, so no adapter import is needed — and reads nothing Kubernetes-shaped.
func TestTheCommandBoundaryImportsNoKubernetesLibrary(t *testing.T) {
	checked := 0
	for _, name := range cliProductionFiles(t) {
		checked++
		for _, imported := range parseCLIFile(t, name).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if strings.HasPrefix(path, "k8s.io/") || strings.HasPrefix(path, "sigs.k8s.io/") {
				t.Errorf("%s imports %s.\n\n"+
					"internal/adapter/kubernetes/client is the sole importer; every "+
					"other layer consumes svcdoctor's own normalized values "+
					"(ADR 0094 §2.10).", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no production file was scanned; this guard would pass vacuously")
	}
}

// TestTheCommandBoundaryOpensNoSecret.
//
// `forbidigo` fails the build on a `security.Reveal` outside an authorized
// package, and this says the narrower thing the new command makes worth saying:
// the leaf holds a `security.Secret` on its way to `app`, and never opens it.
func TestTheCommandBoundaryOpensNoSecret(t *testing.T) {
	checked := 0
	for _, name := range cliProductionFiles(t) {
		checked++
		ast.Inspect(parseCLIFile(t, name), func(n ast.Node) bool {
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
			if pkg.Name == "security" && sel.Sel.Name == "Reveal" {
				t.Errorf("%s calls security.Reveal.\n\n"+
					"Each service has exactly one authorized site and none of them is "+
					"here; the command binds a secret to an endpoint and hands it on.",
					name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no production file was scanned; this guard would pass vacuously")
	}
}

// --- the generic secret helper stayed generic -------------------------------

// TestTheCredentialSourceHelperNamesTheCallersFlags.
//
// Phase 12.1C.2 parameterized `credentialSources` with the two flag names, and
// §35 of that phase required proof in both directions: the four existing
// commands must produce **byte-identical** messages, and the fifth must produce
// its own. A helper that had grown a service branch, or a default favouring the
// password pair, would fail one half or the other.
func TestTheCredentialSourceHelperNamesTheCallersFlags(t *testing.T) {
	tests := []struct {
		sources credentialSources
		want    string
	}{
		{
			credentialSources{
				file: "f", fromStdin: true,
				fileFlag: "password-file", stdinFlag: "password-stdin",
			},
			"--password-file and --password-stdin are mutually exclusive",
		},
		{
			credentialSources{
				file: "f", fromStdin: true,
				fileFlag: "token-file", stdinFlag: "token-stdin",
			},
			"--token-file and --token-stdin are mutually exclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			err := tt.sources.validate()
			if err == nil {
				t.Fatal("two sources were accepted")
			}
			if got := err.Error(); !strings.Contains(got, tt.want) {
				t.Errorf("want %q\ngot  %q", tt.want, got)
			}
		})
	}
}

// TestTheFourExistingCommandsStillNameThePasswordFlags drives the real parsers,
// so a message that changed anywhere on the path fails here rather than in a
// release note.
func TestTheFourExistingCommandsStillNameThePasswordFlags(t *testing.T) {
	invocations := map[string][]string{
		"postgres": {"--host", "h", "--user", "u"},
		"kafka":    {"--host", "h", "--sasl-mechanism", "PLAIN", "--user", "u"},
		"redis":    {"--host", "h"},
		"rabbitmq": {"--host", "h"},
	}

	for service, base := range invocations {
		t.Run(service, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &App{
				In: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr, Version: "test",
			}
			args := append([]string{"diagnose", service}, base...)
			args = append(args, "--password-file", "/nonexistent", "--password-stdin")

			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Errorf("exited %d, want %d", code, ExitUsage)
			}
			want := "--password-file and --password-stdin are mutually exclusive"
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("the message changed.\nwant %q\ngot  %s", want, stderr.String())
			}
		})
	}
}

// TestTheSecretHelperKnowsNoServiceName is the architectural half of §35.
//
// The helper carries flag names as data. The day it can tell which service is
// asking is the day it stopped being generic, and a service name in the file is
// how that would look.
func TestTheSecretHelperKnowsNoServiceName(t *testing.T) {
	source := string(readCLIFileBytes(t, "secret.go"))
	for _, service := range []string{
		"Kubernetes", "kubernetes", "PostgreSQL", "Kafka", "RabbitMQ", "Redis", "Valkey",
	} {
		// The doc comment may *name* a service to explain why the pair is a
		// parameter; the code may not branch on one. Only executable text is
		// scanned.
		for _, line := range strings.Split(source, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || trimmed == "" {
				continue
			}
			if strings.Contains(line, service) {
				t.Errorf("secret.go's executable text names %q: %s\n\n"+
					"The helper holds ADR 0049's read semantics and no service "+
					"knowledge; naming one is how a branch on one begins.", service, line)
			}
		}
	}
}

// --- helpers ----------------------------------------------------------------

// kubernetesTestApp builds an App whose run seam fails loudly.
//
// Every test in this file is about the parse and refusal half, so a run that
// starts is itself the defect: an invalid configuration must be decided before
// anything is dialled.
func kubernetesTestApp(t *testing.T, stdin string) *App {
	t.Helper()
	var stdout, stderr bytes.Buffer
	a := &App{
		In: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr, Version: "test",
	}
	a.diagnoseKubernetes = func(context.Context, app.KubernetesParams) (app.Result, error) {
		t.Error("a run started; this file only exercises invocations that must be " +
			"refused before anything is dialled")
		return app.Result{}, nil
	}
	return a
}

// kubernetesTokenFile writes bearer-token material and returns its path.
func kubernetesTokenFile(t *testing.T, contents string) string {
	t.Helper()
	return writeFile(t, contents)
}

// kubernetesTokenlessKubeconfig writes a kubeconfig whose user carries no
// credential, so a declared token is the run's only identity.
//
// The server is an address nothing resolves, because nothing here connects: the
// parse path reads the file and derives an endpoint, and that is all.
func kubernetesTokenlessKubeconfig(t *testing.T) string {
	t.Helper()
	return writeFile(t, "apiVersion: v1\nkind: Config\n"+
		"clusters:\n- name: c\n  cluster:\n    server: https://api.example.invalid:6443\n"+
		"users:\n- name: u\n  user: {}\n"+
		"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n")
}

// kubernetesTokenKubeconfig writes a kubeconfig whose user already carries a
// token, for the ambiguity case.
func kubernetesTokenKubeconfig(t *testing.T) string {
	t.Helper()
	return writeFile(t, "apiVersion: v1\nkind: Config\n"+
		"clusters:\n- name: c\n  cluster:\n    server: https://api.example.invalid:6443\n"+
		"users:\n- name: u\n  user:\n    token: in-the-kubeconfig\n"+
		"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n")
}

// readCLIFileBytes reads one production file of this package.
func readCLIFileBytes(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return body
}

// kubernetesDefinedFlags reads the flag names parseKubernetes registers.
func kubernetesDefinedFlags(t *testing.T) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	ast.Inspect(parseCLIFile(t, "kubernetes.go"), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "String", "Uint", "Bool", "Duration", "Int":
		default:
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "fs" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		out[strings.Trim(lit.Value, `"`)] = true
		return true
	})
	return out
}
