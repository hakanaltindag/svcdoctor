package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// Phase 12.1C.2's properties and its one fuzz target.
//
// # What earns a property here, and what does not
//
// A property is worth writing when a *class* of input has to behave one way and
// enumerating the class is not possible. Three do. The flag surface has to be
// exactly ten however the arguments are permuted; **any** flag outside the
// frozen set has to be refused, including ones nobody has thought of; and an
// operator-supplied name, whatever bytes it holds, must never reach an output
// stream unless the run actually completed with it.
//
// The fuzz target is the last of those, because it is the only one whose input
// space is genuinely open. `--namespace` and `--service-name` are the two values
// an operator types that end up in an evidence subject, an identifier and a
// redaction table, so they are where a hostile string would have to enter.

// TestKP01TheFlagSurfaceIsOrderIndependent.
//
// Ten flags, whatever order they arrive in. `flag` is order-independent by
// construction, so this is cheap; it is here because the *validation* order is
// not — the command checks the invocation, then the target, then the credential
// — and a rule that only fired when its flag came first would pass every
// table-driven test written in the obvious order.
func TestKP01TheFlagSurfaceIsOrderIndependent(t *testing.T) {
	permutations := [][]string{
		{"--in-cluster", "--namespace", "n", "--service-name", "s"},
		{"--namespace", "n", "--in-cluster", "--service-name", "s"},
		{"--service-name", "s", "--namespace", "n", "--in-cluster"},
		{"--service-name", "s", "--in-cluster", "--namespace", "n"},
	}

	for _, args := range permutations {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			a := kubernetesTestApp(t, "")
			command, err := a.parseKubernetes(args)
			if err != nil {
				t.Fatalf("a valid in-cluster invocation was refused: %v", err)
			}
			if command.params.Target.Namespace != "n" ||
				command.params.Target.ServiceName != "s" ||
				!command.params.Target.InCluster {
				t.Errorf("argument order changed the target: %+v", command.params.Target)
			}
		})
	}
}

// TestKP02AnyFlagOutsideTheFrozenSetIsRefused.
//
// The forbidden list in `kubernetes_test.go` enumerates the flags somebody would
// plausibly add. This states the rule the list is a sample of: **the surface is
// closed**, so a name nobody predicted is refused for the same reason.
//
// The generator is deliberately dull — it builds names out of the vocabulary the
// domain uses — because an unlikely name proves less than a likely one.
func TestKP02AnyFlagOutsideTheFrozenSetIsRefused(t *testing.T) {
	prefixes := []string{"", "k8s-", "kube-", "cluster-", "api-", "no-", "allow-", "skip-"}
	stems := []string{
		"namespace", "service", "selector", "pod", "endpoint", "token", "cert",
		"insecure", "timeout", "budget", "page", "verbose", "debug", "watch",
	}
	suffixes := []string{"", "s", "-name", "-file", "-url", "-mode", "-limit", "-check"}

	checked := 0
	for _, prefix := range prefixes {
		for _, stem := range stems {
			for _, suffix := range suffixes {
				name := prefix + stem + suffix
				if kubernetesFlags[name] {
					continue // A frozen flag is not an outsider.
				}
				checked++

				a := kubernetesTestApp(t, "")
				code := a.Run(context.Background(), []string{
					"diagnose", "kubernetes", "--in-cluster",
					"--namespace", "n", "--service-name", "s", "--" + name + "=x",
				})
				if code != ExitUsage {
					t.Errorf("--%s exited %d, want %d; the Kubernetes flag surface is "+
						"closed at ten", name, code, ExitUsage)
				}
			}
		}
	}
	// Non-vacuity: the generator must actually have produced outsiders, and it
	// must also have skipped at least one frozen name, or it is testing a set
	// that happens not to overlap the surface at all.
	if checked < 100 {
		t.Fatalf("only %d candidate flags were generated; this property would be weak",
			checked)
	}
	if !kubernetesFlags["namespace"] || !kubernetesFlags["timeout"] {
		t.Fatal("the generator's overlap with the frozen surface is gone, so the skip " +
			"branch above is never taken and the property is not what it claims")
	}
}

// TestKP03AnInvalidInvocationNeverStartsARun.
//
// The seam in kubernetesTestApp fails the test if a run begins, so this is the
// same property `test/fleet` measures at a request-counting server, stated one
// layer up where it is cheap enough to drive over many rows. The two together
// are the claim: nothing is dialled, and nothing is even asked to dial.
func TestKP03AnInvalidInvocationNeverStartsARun(t *testing.T) {
	invocations := [][]string{
		{},
		{"--namespace", "n"},
		{"--service-name", "s"},
		{"--in-cluster", "--kubeconfig", "/nonexistent"},
		{"--in-cluster", "--context", "c", "--namespace", "n", "--service-name", "s"},
		{"--kubeconfig", "/nonexistent", "--namespace", "n", "--service-name", "s"},
		{"--in-cluster", "--namespace", "", "--service-name", "s"},
		{"--in-cluster", "--namespace", "n", "--service-name", ""},
		{"--in-cluster", "--namespace", "n", "--service-name", "s", "--timeout", "-1s"},
		{"--in-cluster", "--namespace", "n", "--service-name", "s", "--output", "xml"},
		{"--in-cluster", "--namespace", "n", "--service-name", "s", "extra-argument"},
	}

	for _, args := range invocations {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			a := kubernetesTestApp(t, "")
			code := a.Run(context.Background(),
				append([]string{"diagnose", "kubernetes"}, args...))
			if code != ExitUsage {
				t.Errorf("exited %d, want %d", code, ExitUsage)
			}
		})
	}
}

// TestKP04AnOperatorSuppliedNameIsNeverEchoedRaw.
//
// A namespace and a Service name are the two values an operator types that reach
// an evidence subject. `checkName` refuses a name carrying a control character,
// whitespace or the separator the identifier encoding reserves — and this states
// the consequence the refusal exists for: **whatever is refused is never quoted
// back**, because quoting attacker-chosen bytes into a diagnostic is how a
// refusal becomes an injection.
//
// It asserts the narrow, checkable thing rather than a vague one: the refusal
// message is well-formed UTF-8 with no control characters, whatever went in.
func TestKP04AnOperatorSuppliedNameIsNeverEchoedRaw(t *testing.T) {
	hostile := []string{
		"a\x00b", "a\tb", "a\nb", "a\rb", "a b", "a/b", "a%b",
		"\x1b[31mred", "../../etc/passwd", "a\x7fb",
		strings.Repeat("x", 4096),
	}

	for _, name := range hostile {
		t.Run(strings.ToValidUTF8(name, "?"), func(t *testing.T) {
			for _, field := range []string{"--namespace", "--service-name"} {
				a := kubernetesTestApp(t, "")
				args := []string{"diagnose", "kubernetes", "--in-cluster",
					"--namespace", "ok", "--service-name", "ok"}
				for i, value := range args {
					if value == field {
						args[i+1] = name
					}
				}

				var stderr strings.Builder
				a.Stderr = &stderr
				code := a.Run(context.Background(), args)

				if code != ExitUsage {
					t.Errorf("%s %q exited %d, want %d", field, name, code, ExitUsage)
				}
				assertQuotableDiagnostic(t, stderr.String())
			}
		})
	}
}

// assertQuotableDiagnostic checks that a diagnostic is safe to put on a terminal.
//
// Valid UTF-8 and no C0 control character other than the newline that ends a
// line. An escape sequence reaching a terminal from a value an operator or a
// cluster supplied is the whole reason this is asserted rather than assumed.
func assertQuotableDiagnostic(t *testing.T, body string) {
	t.Helper()

	if !utf8.ValidString(body) {
		t.Errorf("the diagnostic is not valid UTF-8: %q", body)
	}
	for _, r := range body {
		if r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			t.Errorf("the diagnostic carries the control character %q: %q", r, body)
			return
		}
	}
}

// FuzzTheKubernetesTargetNamesAreNeverEchoed is the one fuzz target this phase
// adds, and it tests a real boundary rather than coverage.
//
// `--namespace` and `--service-name` are validated by `checkName`, whose whole
// job is to decide what may become an evidence subject, an `EvidenceID` and a
// redaction-table key. So the property is a **dichotomy**, and both halves
// matter:
//
//   - refused ⇒ exit 2, nothing on stdout, and a diagnostic that is valid UTF-8
//     with no control character. Quoting attacker-chosen bytes into a message an
//     operator will read on a terminal is how a refusal becomes an injection.
//   - accepted ⇒ the value reaches the target **byte for byte**. A name
//     svcdoctor silently trimmed, escaped or normalized would produce a report
//     about a Service the operator did not name, which `checkName`'s own comment
//     calls out as the reason it refuses rather than mangles.
//
// # The first version of this target was wrong, and the fuzzer said so
//
// It asserted that every input is refused. Seed `"payments-api"` is a perfectly
// good name, so the run started and the seam fired — a defect in the test rather
// than in production, found in under a second. The dichotomy above is what the
// boundary actually promises, and it is strictly stronger: the old form could
// not have caught a mangled-but-accepted name at all.
//
// It reaches no network: the seam returns without running, so an accepted name
// is observed rather than dialled.
func FuzzTheKubernetesTargetNamesAreNeverEchoed(f *testing.F) {
	for _, seed := range []string{
		"payments", "payments-api", "", " ", "a/b", "a%b", "\x00", "\x1b[31m",
		"\n", "\t", strings.Repeat("n", 300), "ünïcödé", "🙂",
	} {
		f.Add(seed, seed)
	}

	f.Fuzz(func(t *testing.T, namespace, serviceName string) {
		var stdout, stderr strings.Builder

		var started bool
		var accepted app.KubernetesTarget
		a := &App{
			In: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr, Version: "test",
		}
		a.diagnoseKubernetes = func(
			_ context.Context, params app.KubernetesParams,
		) (app.Result, error) {
			started = true
			accepted = params.Target
			// A canned refusal, so nothing is dialled and the output half of
			// the command is not exercised by a fuzzed input.
			return app.Result{}, errFuzzRunObserved
		}

		code := a.Run(context.Background(), []string{
			"diagnose", "kubernetes", "--in-cluster",
			"--namespace", namespace, "--service-name", serviceName,
		})

		if !started {
			// Refused. It must be a usage error, it must print nothing to
			// stdout, and the diagnostic must be safe to display.
			if code != ExitUsage {
				t.Fatalf("namespace %q / service name %q was refused with exit %d, "+
					"want %d; a malformed name is something the operator wrote",
					namespace, serviceName, code, ExitUsage)
			}
			if stdout.String() != "" {
				t.Fatalf("a refused invocation wrote to stdout: %q", stdout.String())
			}
			assertQuotableDiagnostic(t, stderr.String())
			return
		}

		// Accepted. The names must have arrived unmodified: svcdoctor refuses a
		// name it cannot use rather than repairing one, so any difference here
		// would mean a report about a Service nobody named.
		if accepted.Namespace != namespace {
			t.Fatalf("the namespace was modified on the way to the target: "+
				"%q became %q", namespace, accepted.Namespace)
		}
		if accepted.ServiceName != serviceName {
			t.Fatalf("the service name was modified on the way to the target: "+
				"%q became %q", serviceName, accepted.ServiceName)
		}
		if !accepted.InCluster || accepted.Kubeconfig != "" || accepted.Context != "" {
			t.Fatalf("the authority changed: %+v", accepted)
		}
		assertQuotableDiagnostic(t, stderr.String())
	})
}

// errFuzzRunObserved lets the fuzz seam report that a run began without dialling.
//
// It wraps app.ErrInvalidInput so the exit mapping treats it as a usage error
// rather than as an internal failure — the fuzz target asserts on `started`
// rather than on the code in that branch, and a 3 in the log would read as a
// defect it is not.
var errFuzzRunObserved = fmt.Errorf("%w: the fuzz seam observed a run", app.ErrInvalidInput)
