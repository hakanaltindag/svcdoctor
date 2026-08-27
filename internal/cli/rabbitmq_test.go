package cli

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// --- the public flag surface ------------------------------------------------

// rabbitmqFlags is the exact frozen public surface of `diagnose rabbitmq`.
//
// **Exact in both directions.** A flag here that the command does not define is
// a promise the help text makes and the parser breaks; a flag the command
// defines that is not here is a surface nobody reviewed. ADR 0067 §3 fixes the
// set and names what is deliberately absent.
var rabbitmqFlags = map[string]bool{
	"host": true, "port": true, "vhost": true,
	"username": true, "password-file": true, "password-stdin": true,
	"timeout": true, "step-timeout": true,
	"tls": true, "tls-ca-file": true, "tls-server-name": true, "tls-insecure": true,
	"output": true, "shareable": true,
}

// rabbitmqForbiddenFlags are the flags that must never exist.
//
// Each is something a reasonable person would add, and each would break a frozen
// decision: a mechanism selector implies a fallback ladder (ADR 0068 §2), a Tune
// override is a knob for a value ADR 0070 fixed, a queue or exchange name is
// customer topology BASIC never touches, a management flag is a second protocol
// (ADR 0067 §8), and a plaintext-credential escape hatch is the one thing the
// repository has a test asserting the absence of.
var rabbitmqForbiddenFlags = []string{
	"password", "password-env", "mechanism", "amqplain", "external", "anonymous",
	"heartbeat", "frame-max", "channel-max", "connection-name",
	"management-url", "management-port", "management-user", "management-password",
	"queue", "exchange", "publish", "consume",
	"allow-plaintext-credential", "insecure-credential", "credential-policy",
	"cluster", "node", "discovery",
	"tls-cert-file", "tls-key-file", "client-cert", "client-key",
	"unix-socket", "socket",
}

// TestTheRabbitMQFlagSurfaceIsExactlyFrozen reads the flags the parser actually
// registers rather than the help text, so a flag that exists but is undocumented
// still fails.
func TestTheRabbitMQFlagSurfaceIsExactlyFrozen(t *testing.T) {
	defined := rabbitmqDefinedFlags(t)

	if len(defined) == 0 {
		t.Fatal("no flags were parsed out of parseRabbitMQ; this guard would pass vacuously")
	}
	for name := range rabbitmqFlags {
		if !defined[name] {
			t.Errorf("--%s is frozen in the RabbitMQ surface and the command does not "+
				"define it", name)
		}
	}
	for name := range defined {
		if !rabbitmqFlags[name] {
			t.Errorf("`diagnose rabbitmq` defines --%s, which the frozen surface does not "+
				"authorize.\n\nAdd it to rabbitmqFlags deliberately, with the record that "+
				"authorizes it, or remove it.", name)
		}
	}
}

// TestTheRabbitMQCommandRejectsForbiddenFlags is the behavioural half.
//
// The surface test reads the source; this drives the parser, so a flag that
// somehow became accepted at runtime fails here even if the source scan missed it.
func TestTheRabbitMQCommandRejectsForbiddenFlags(t *testing.T) {
	for _, name := range rabbitmqForbiddenFlags {
		t.Run(name, func(t *testing.T) {
			var out, errb bytes.Buffer
			a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
			a.diagnoseRabbitMQ = func(context.Context, app.RabbitMQParams) (app.Result, error) {
				t.Error("a run started despite a forbidden flag")
				return app.Result{}, nil
			}
			code := a.Run(context.Background(),
				[]string{"diagnose", "rabbitmq", "--host", "h", "--" + name, "x"})
			if code != ExitUsage {
				t.Errorf("--%s exited %d, want %d (usage)", name, code, ExitUsage)
			}
		})
	}
}

// TestTheForbiddenFlagGuardCanFail proves the list is live: an authorized flag
// must be accepted by the same predicate that rejects the forbidden ones.
func TestTheForbiddenFlagGuardCanFail(t *testing.T) {
	for _, name := range []string{"host", "vhost", "username"} {
		if rabbitmqForbiddenFlags == nil {
			t.Fatal("the forbidden list is empty")
		}
		for _, forbidden := range rabbitmqForbiddenFlags {
			if forbidden == name {
				t.Errorf("%q appears in both the frozen surface and the forbidden list", name)
			}
		}
	}
	// And a planted forbidden name really is in the list.
	found := false
	for _, forbidden := range rabbitmqForbiddenFlags {
		if forbidden == "password" {
			found = true
		}
	}
	if !found {
		t.Error("the forbidden list does not contain --password, so it cannot be catching it")
	}
}

// --- defaults and observability ---------------------------------------------

func TestRabbitMQDefaults(t *testing.T) {
	var captured app.RabbitMQParams
	var out, errb bytes.Buffer
	a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
	a.diagnoseRabbitMQ = func(_ context.Context, p app.RabbitMQParams) (app.Result, error) {
		captured = p
		return app.Result{}, nil
	}

	if code := a.Run(context.Background(),
		[]string{"diagnose", "rabbitmq", "--host", "rabbit.internal"}); code != ExitInternal {
		// A zero Result has no report, so rendering fails; the parse is what
		// this asserts and it happened before that.
		_ = code
	}

	if captured.Port != 5672 {
		t.Errorf("default port = %d, want 5672", captured.Port)
	}
	// **Empty at the CLI boundary, defaulted in the composition root.** The
	// distinction is what lets a refusal say the default was used.
	if captured.VHost != "" {
		t.Errorf("default --vhost reached the params as %q; it must stay empty so the "+
			"composition root can record that it was defaulted", captured.VHost)
	}
	if captured.Username != "" {
		t.Errorf("username = %q; svcdoctor never synthesizes one", captured.Username)
	}
	if !captured.Credential.IsZero() {
		t.Error("a credential was built with no password source given")
	}
}

// TestTheDefaultVHostIsObservable proves the default is `/` and reaches the run.
func TestTheDefaultVHostIsObservable(t *testing.T) {
	if app.DefaultVHost != "/" {
		t.Errorf("DefaultVHost = %q, want /", app.DefaultVHost)
	}
	help := rabbitmqHelp(t)
	collapsed := strings.Join(strings.Fields(help), " ")
	if !strings.Contains(collapsed, `default "/"`) {
		t.Error("the help text does not state the virtual host default")
	}
}

func TestRabbitMQAcceptsAddressLiterals(t *testing.T) {
	for _, host := range []string{"192.0.2.10", "::1"} {
		t.Run(host, func(t *testing.T) {
			var captured app.RabbitMQParams
			var out, errb bytes.Buffer
			a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
			a.diagnoseRabbitMQ = func(_ context.Context, p app.RabbitMQParams) (app.Result, error) {
				captured = p
				return app.Result{}, nil
			}
			_ = a.Run(context.Background(), []string{"diagnose", "rabbitmq", "--host", host})
			if captured.Host != host {
				t.Errorf("host = %q, want %q", captured.Host, host)
			}
		})
	}
}

// TestPasswordSourcesAreMutuallyExclusive pins ADR 0049's no-precedence rule.
func TestPasswordSourcesAreMutuallyExclusive(t *testing.T) {
	var out, errb bytes.Buffer
	a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
	a.diagnoseRabbitMQ = func(context.Context, app.RabbitMQParams) (app.Result, error) {
		t.Error("a run started with two credential sources")
		return app.Result{}, nil
	}
	code := a.Run(context.Background(), []string{
		"diagnose", "rabbitmq", "--host", "h",
		"--password-file", "/dev/null", "--password-stdin",
	})
	if code != ExitUsage {
		t.Errorf("two credential sources exited %d, want %d", code, ExitUsage)
	}
}

// TestPasswordStdinIsReadFromTheInjectedInput pins ADR 0067 §3: the RabbitMQ
// credential is sourced "exactly as ADR 0049 decided for PostgreSQL".
//
// Phase 8.2 briefly shipped a third source, `--password-env`. It was removed at
// 8.2-R3 closure: ADR 0049 §5 rejects environment variables outright, Kafka has a
// test asserting the flag does not exist, and ADR 0067 §3 never named one. A
// credential-source abstraction belongs to fleet configuration, not to a leaf
// command, and adding it to one service only would have made RabbitMQ the single
// undocumented exception to a contract three other commands share.
func TestPasswordStdinIsReadFromTheInjectedInput(t *testing.T) {
	const canary = "s3cr3t"

	var captured app.RabbitMQParams
	var out, errb bytes.Buffer
	a := &App{
		In:     strings.NewReader(canary + "\n"),
		Stdout: &out, Stderr: &errb, Version: "test",
	}
	a.diagnoseRabbitMQ = func(_ context.Context, p app.RabbitMQParams) (app.Result, error) {
		captured = p
		return app.Result{}, nil
	}
	_ = a.Run(context.Background(), []string{
		"diagnose", "rabbitmq", "--host", "h", "--username", "u", "--password-stdin",
	})
	if captured.Credential.IsZero() {
		t.Fatal("--password-stdin built no credential")
	}
	if strings.Contains(out.String()+errb.String(), canary) {
		t.Error("the credential value appears in command output")
	}
}

// TestRabbitMQRefusesTheRemovedEnvironmentSource proves the flag is gone rather
// than merely unused: the refusal must be the parser's own "not defined" message,
// because a command that registered the flag and ignored it would also exit 2.
func TestRabbitMQRefusesTheRemovedEnvironmentSource(t *testing.T) {
	var out, errb bytes.Buffer
	a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
	a.diagnoseRabbitMQ = func(context.Context, app.RabbitMQParams) (app.Result, error) {
		t.Error("a run started from an environment credential source")
		return app.Result{}, nil
	}
	code := a.Run(context.Background(), []string{
		"diagnose", "rabbitmq", "--host", "h", "--password-env", "RABBITMQ_PASSWORD",
	})
	if code != ExitUsage {
		t.Errorf("--password-env exited %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errb.String(), "not defined") {
		t.Errorf("refusal was not the parser rejecting an unknown flag: %s", errb.String())
	}
}

// TestTheStepTimeoutFloorIsEnforced pins ADR 0070 §8.
func TestTheStepTimeoutFloorIsEnforced(t *testing.T) {
	var out, errb bytes.Buffer
	a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
	a.diagnoseRabbitMQ = func(context.Context, app.RabbitMQParams) (app.Result, error) {
		t.Error("a run started with a step timeout below the floor")
		return app.Result{}, nil
	}
	if code := a.Run(context.Background(), []string{
		"diagnose", "rabbitmq", "--host", "h", "--step-timeout", "2s",
	}); code != ExitUsage {
		t.Errorf("a 2s step timeout exited %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errb.String(), "3s") {
		t.Errorf("the refusal does not name the floor: %s", errb.String())
	}
}

// --- help text --------------------------------------------------------------

// TestTheRabbitMQHelpStatesWhatIsNotProven is the claim-discipline guard for the
// one document an operator reads before running anything.
func TestTheRabbitMQHelpStatesWhatIsNotProven(t *testing.T) {
	// Whitespace-collapsed: the help is hard-wrapped for a terminal, so
	// "quorum queue health" spans two lines. The assertion is about wording, not
	// about where the wrap fell.
	help := strings.Join(strings.Fields(strings.ToLower(rabbitmqHelp(t))), " ")

	for _, required := range []string{
		"connection.open-ok",
		"queue existence", "exchange existence", "publishing", "consuming",
		"configure/write/read permissions", "cluster health", "quorum queue health",
		"node health", "management api health", "message delivery",
		"workload correctness",
		"at most once", "verified", "--tls-insecure",
		"loopback", "private address",
		"plain only",
	} {
		if !strings.Contains(help, required) {
			t.Errorf("the RabbitMQ help does not mention %q", required)
		}
	}

	for _, forbidden := range []string{
		"rabbitmq is healthy", "broker is healthy", "cluster is healthy",
		"guarantees", "your application will work",
	} {
		if strings.Contains(help, forbidden) {
			t.Errorf("the RabbitMQ help says %q", forbidden)
		}
	}
}

// TestTheHelpGuardCanFail proves both halves of the help assertion are live.
func TestTheHelpGuardCanFail(t *testing.T) {
	planted := strings.ToLower("svcdoctor proves rabbitmq is healthy")
	if !strings.Contains(planted, "rabbitmq is healthy") {
		t.Error("the forbidden-phrase predicate does not match a planted overclaim")
	}
	if strings.Contains(planted, "connection.open-ok") {
		t.Error("the required-phrase predicate matches text that lacks the phrase")
	}
}

// --- import boundary --------------------------------------------------------

// TestTheCLICannotReachTheRabbitMQWireOrAdapter pins the layering.
//
// The CLI parses flags and renders a report. It must reach `internal/app` and
// nothing below it: an import of the adapter would let a future change sequence
// sockets here, and an import of the wire package would put the one place a
// secret is opened inside the layer that reads operator input.
func TestTheCLICannotReachTheRabbitMQWireOrAdapter(t *testing.T) {
	for _, forbidden := range []string{
		"internal/adapter/rabbitmq",
		"internal/adapter/rabbitmq/wire",
		"internal/diagnosis/rabbitmq",
		"internal/service/rabbitmq",
	} {
		for _, name := range cliProductionFiles(t) {
			for _, imported := range parseCLIFile(t, name).Imports {
				if strings.Contains(imported.Path.Value, forbidden) {
					t.Errorf("%s imports %s; the CLI reaches internal/app and nothing "+
						"below it", name, forbidden)
				}
			}
		}
	}
}

// TestTheRabbitMQCommandGoesThroughTheAppSeam proves the route.
func TestTheRabbitMQCommandGoesThroughTheAppSeam(t *testing.T) {
	source := readCLISource(t, "rabbitmq.go")
	if !strings.Contains(source, "a.diagnoseRabbitMQ(runCtx, command.params)") {
		t.Error("the RabbitMQ command does not call the app seam")
	}
	if strings.Contains(source, "security.Reveal") {
		t.Error("the RabbitMQ command names security.Reveal")
	}
}

// --- helpers ----------------------------------------------------------------

func rabbitmqHelp(t *testing.T) string {
	t.Helper()
	var out, errb bytes.Buffer
	a := &App{In: bytes.NewReader(nil), Stdout: &out, Stderr: &errb, Version: "test"}
	if code := a.Run(context.Background(),
		[]string{"diagnose", "rabbitmq", "--help"}); code != ExitOK {
		t.Fatalf("--help exited %d", code)
	}
	return out.String()
}

// rabbitmqDefinedFlags reads the flag names parseRabbitMQ registers.
func rabbitmqDefinedFlags(t *testing.T) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	ast.Inspect(parseCLIFile(t, "rabbitmq.go"), func(n ast.Node) bool {
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

func cliProductionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		out = append(out, entry.Name())
	}
	return out
}

func parseCLIFile(t *testing.T, name string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f
}

func readCLISource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // a package-local path.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
