package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/platform/local"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// kubernetesCommand is one parsed `diagnose kubernetes` invocation.
type kubernetesCommand struct {
	timeout   time.Duration
	output    string
	shareable bool
	params    app.KubernetesParams
}

// diagnoseKubernetesCommand reads one Kubernetes Service's backend publication.
//
// It is the fifth sibling of the PostgreSQL, Kafka, Redis and RabbitMQ commands
// and has the same shape for the same reason: each service owns its flags, help
// and validation, and the five share the word `diagnose`, the exit mapping, the
// credential sources and the output switch — and no service knowledge at all.
//
// # It is the first leaf that names no endpoint, and that is the shape
//
// The other four are asked about a logical endpoint an operator typed. This one
// is asked about a **Service object** — one namespace and one name — and the API
// server it is read through is derived from the authority the target already
// names (ADR 0094 §2.4). So there is no `--host` and no `--port`: the pair that
// would fill them is computed, is what the credential binds to, and is
// deliberately not published as the run's identity.
//
// # It connects to nothing the Service describes
//
// Three bounded API reads and no more: the Service, the Pods its own selector
// matches, and the EndpointSlices Kubernetes associates with it. svcdoctor
// reaches no Pod, no cluster IP and no endpoint address, so no claim in the
// report is about reachability — it reports what Kubernetes **publishes**.
func (a *App) diagnoseKubernetesCommand(ctx context.Context, args []string) int {
	command, err := a.parseKubernetes(args)
	if errors.Is(err, errHelpRequested) {
		return ExitOK
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitCode(app.Result{}, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	result, runErr := a.diagnoseKubernetes(runCtx, command.params)
	code := ExitCode(result, runErr)
	if runErr != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", runErr)
		return code
	}

	report, err := project(result.Report(), command.shareable)
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	if err := a.render(command.output,
		render.Input{Report: report, Incomplete: result.Incomplete()}); err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	return code
}

// parseKubernetes turns arguments into one run's parameters.
//
// # Ten flags, and the tenth is the last
//
// `PHASE121C1…§5` froze the surface and `TestTheKubernetesFlagSurfaceIsExact`
// pins it from outside. Five of the ten map one-to-one onto the five fields
// Phase 12.1B froze on the target — and there is deliberately no sixth field, so
// there can be no sixth target flag. `--token-file` is the one flag a Kubernetes
// source names by name (`PHASE121A…§6.1` mode A) and `--token-stdin` is ADR
// 0049's other half of it.
//
// What is absent, and why each absence is a decision rather than an omission:
//
//   - No `--host` or `--port`: the API server is derived, never typed (§2.4).
//   - No `--server` or `--api-server`: *"server / cluster override: none. The
//     context selects the cluster"* (`PHASE121A…§6.3`).
//   - No `--user`: a bearer token and a client certificate each **are** the
//     identity, and the API server decides who they name. Basic authentication
//     is refused outright.
//   - No `--client-cert` or `--client-key`: that mode is reached through the
//     kubeconfig, which is the only place the target model has to put it.
//     Adding flags would be a second Kubernetes configuration model, and a leaf
//     invocation could then express an identity a `run --config` target cannot.
//   - No `--token` taking a value: a secret in argv lands in shell history and
//     the process table (ADR 0049 §5).
//   - No TLS flag: the API server's trust material comes from the kubeconfig's
//     own `certificate-authority`, or from the projected ServiceAccount CA
//     in-cluster. `--tls-insecure` has no Kubernetes spelling at all — svcdoctor
//     presents a credential there and will not do so over a channel it cannot
//     verify, in any mode.
//   - No `--step-timeout`: a Kubernetes run has no per-step budget to bound.
//     Three requests run under one deadline, and a flag that changed nothing
//     would be the inert configuration ADR 0060 refuses.
//   - No budget flag: ADR 0094 §2.5 froze the five acquisition numbers, and a
//     budget is a *completeness* input — lowering one makes a set incomplete,
//     and both universal findings require a complete enumeration, so a flag
//     there could silently suppress a finding.
//   - No `--all-namespaces`, `--selector`, `--pod`, `--deployment`, `--events`,
//     `--logs` or `--metrics`: MVP-D admits one Service, and there is no per-Pod
//     and no per-endpoint evidence for any of them to render.
//
// # It validates the invocation and nothing about Kubernetes
//
// Whether the target's shape is legal, whether the kubeconfig parses, whether it
// names the context, and whether it carries a construct svcdoctor refuses are
// **one question with one owner**: the adapter, reached through
// app.InspectKubernetesTarget, which performs no network operation. This
// function restates none of it. Duplicating those rules here would be a second
// Kubernetes validator that could disagree with the first, and the fleet
// decoder — which asks the same function the same question — would then answer
// differently from the command for the same file.
func (a *App) parseKubernetes(args []string) (kubernetesCommand, error) {
	fs := flag.NewFlagSet("diagnose kubernetes", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		kubeconfig  = fs.String("kubeconfig", "", "path to exactly one kubeconfig file")
		context     = fs.String("context", "", "the kubeconfig context to read through")
		inCluster   = fs.Bool("in-cluster", false, "authenticate as the pod's ServiceAccount")
		namespace   = fs.String("namespace", "", "the namespace the Service is in")
		serviceName = fs.String("service-name", "", "the Service to diagnose")
		timeout     = fs.Duration("timeout", 30*time.Second, "bound on the whole run")
		output      = fs.String("output", "text", `"text" or "json"`)

		tokenFile  = fs.String("token-file", "", "read the bearer token from a file")
		tokenStdin = fs.Bool("token-stdin", false, "read the bearer token from stdin")

		shareable = fs.Bool("shareable", false, "produce the shareable redacted report")
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.usageKubernetes(a.Stdout)
			return kubernetesCommand{}, errHelpRequested
		}
		return kubernetesCommand{}, usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return kubernetesCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}

	if *timeout <= 0 {
		return kubernetesCommand{}, usagef("--timeout %s must be positive", *timeout)
	}
	if err := checkOutput(*output); err != nil {
		return kubernetesCommand{}, err
	}

	sources := credentialSources{
		file: *tokenFile, fromStdin: *tokenStdin,
		fileFlag: "token-file", stdinFlag: "token-stdin",
	}
	if err := sources.validate(); err != nil {
		return kubernetesCommand{}, err
	}

	target := app.KubernetesTarget{
		Kubeconfig:  *kubeconfig,
		Context:     *context,
		InCluster:   *inCluster,
		Namespace:   *namespace,
		ServiceName: *serviceName,
	}

	// One question, one owner, and it happens before anything is dialled.
	//
	// It answers three things at once — is the declaration legal, which API
	// server does it resolve to, and does the selected cluster or user carry a
	// construct svcdoctor refuses — and it performs no network operation while
	// doing so. That is what makes an `exec` credential plugin, an
	// auth-provider, impersonation, a `proxy-url` or a disabled verification a
	// **configuration error at exit 2 with zero requests sent**, rather than one
	// run's execution failure.
	//
	// Whether a credential was *declared* is all the ambiguity check needs, and
	// it is knowable here, where nothing has been read: a target naming a token
	// while the selected kubeconfig user also carries one declares two
	// identities, and svcdoctor refuses the ambiguity rather than choosing.
	host, port, err := app.InspectKubernetesTarget(target, sources.declared())
	if err != nil {
		return kubernetesCommand{}, usagef("%v", err)
	}

	secret, err := a.readSecret(sources)
	if err != nil {
		return kubernetesCommand{}, err
	}
	// **A declared source that holds nothing is a usage error**, and this is the
	// one place the Kubernetes command deliberately differs from its four
	// siblings, where an empty source means "no credential" and the run
	// continues to a truthful CREDENTIAL_NOT_CONFIGURED finding at exit 0.
	//
	// Two reasons, both structural. The mode was already chosen: Inspect was
	// told a credential is supplied and selected the bearer-token mode on that
	// basis, refusing any competing kubeconfig credential — so continuing with
	// nothing to present would leave a run authenticating as a mode whose
	// material does not exist. And Kubernetes has **no credential-not-configured
	// finding** and cannot gain one, because ADR 0094 §2.7 freezes the four
	// codes — so silently degrading to a credential-free run would be a fact the
	// report has no way to state. `internal/fleet/secret` already refuses the
	// same shape for the same mode, and this is the leaf's half of it.
	if sources.declared() && secret.IsEmpty() {
		return kubernetesCommand{}, usagef(
			"--%s named a credential source that holds no bearer token; svcdoctor will not "+
				"silently continue without the credential this run asked it to present, and "+
				"it has no way to report that it did", sources.declaredFlag())
	}

	// Bound to the API server and to nothing else.
	//
	// The pair is the one Inspect resolved, so the credential authorizes exactly
	// the authority the target named. ADR 0028's binding check refuses it
	// anywhere else — a Pod IP, a ClusterIP, an endpoint address, another
	// service's endpoint — and the composition root checks the binding rather
	// than trusting it. The identity is empty because a Kubernetes credential
	// carries no username.
	credential, err := credentialFor(host, port, "", secret)
	if err != nil {
		return kubernetesCommand{}, err
	}

	vantage, err := local.Vantage()
	if err != nil {
		return kubernetesCommand{}, usagef("%v", err)
	}

	return kubernetesCommand{
		timeout:   *timeout,
		output:    *output,
		shareable: *shareable,
		params: app.KubernetesParams{
			Target:     target,
			Credential: credential,

			// Budgets is left zero, which is the frozen defaults — the same
			// value `internal/fleet/services/kubernetes` passes. Neither entry
			// point can alter an acquisition budget, so neither can produce a
			// graph the other could not.
			Vantage: vantage,
			Version: a.Version,
		},
	}, nil
}
