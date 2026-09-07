package app

import (
	"context"
	"fmt"
	"time"

	adapterkubernetes "github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes/client"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskubernetes "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// KubernetesTarget is one Kubernetes Service target's declared inputs.
//
// It is an alias rather than a copy. A caller that only composes a run —
// internal/fleet/services/kubernetes, and the leaf command a later phase adds —
// then needs no import of the adapter at all, and there is no second definition
// of the target shape to keep in step with the first.
type KubernetesTarget = client.Target

// InspectKubernetesTarget validates a Kubernetes target and returns the API
// server it resolves to. **It performs no network operation.**
//
// # Why the composition layer exposes this at all
//
// Because a Kubernetes target's usability is decided by a file, and that decision
// has to be made before a run starts. It answers three questions at once: is the
// declaration legal, does the kubeconfig parse and name the context, and does the
// selected cluster or user carry a construct svcdoctor refuses — an `exec`
// credential plugin, an auth-provider, impersonation, a proxy URL, disabled TLS
// verification, basic authentication.
//
// Every one of those is a **configuration error**, so answering early is what
// makes it exit 2 with nothing dialled instead of one target's execution failure
// at exit 4.
//
// The returned host and port are the API server's, and they are the endpoint a
// Kubernetes credential is bound to. They are used for binding and for the
// generic target contract, and are never published as the run's identity.
//
// credentialSupplied says whether the target declares a credential of its own,
// which is all the ambiguity check needs and is knowable before any secret has
// been resolved.
func InspectKubernetesTarget(
	target KubernetesTarget, credentialSupplied bool,
) (host string, port uint16, err error) {
	authority, err := client.Inspect(target, credentialSupplied)
	if err != nil {
		return "", 0, err
	}
	return authority.Endpoint.Host(), authority.Endpoint.Port(), nil
}

// KubernetesParams describes one Kubernetes Service diagnostic run.
//
// # There is no Host and no Port, and that is the shape rather than an omission
//
// Every other service in svcdoctor is asked about a logical endpoint an operator
// typed. A Kubernetes target is asked about a **Service object** — one namespace
// and one name — and the API server it is read through is derived from the
// authority the target already names: the kubeconfig context's `server` URL, or
// the API Service's own name in-cluster. That pair binds the credential and is
// deliberately **not** published as a canonical identifier (ADR 0094 §2.4).
type KubernetesParams struct {
	// Target is the declared API authority, namespace and Service name.
	Target client.Target

	// Credential is a bearer token the target's own credential reference named,
	// already bound to the API server's endpoint. It may be zero, in which case
	// the kubeconfig or the projected ServiceAccount supplies the credential.
	//
	// **It is never rebound here.** A credential arriving bound to a different
	// endpoint is refused rather than re-pointed, which is ADR 0050 section 4's
	// rule and the same check every other composition root performs.
	Credential security.Credential

	// Budgets bound the acquisition. The zero value means the frozen defaults.
	Budgets client.Budgets

	// Vantage records where the run happened.
	Vantage domain.Vantage

	// Version is svcdoctor's own version, recorded in the run metadata.
	Version string
}

func (p KubernetesParams) validate() error {
	switch {
	case p.Vantage.IsZero():
		return fmt.Errorf("%w: vantage must not be zero", ErrInvalidInput)
	case p.Version == "":
		return fmt.Errorf("%w: version must not be empty", ErrInvalidInput)
	}
	if err := p.Target.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return nil
}

// DiagnoseKubernetes reads one Kubernetes Service's publication and reports what
// it found.
//
// # It reads three things and infers none of them
//
// The declared Service, the Pods its own selector matches, and the EndpointSlices
// Kubernetes associates with it. Every one of those is a read the API server
// authorized; svcdoctor connects to no Pod, no cluster IP and no endpoint
// address, so **no claim in the resulting report is about reachability** and the
// Kubernetes credential authorizes exactly one thing — the API server.
//
// # Three rules are wired, and they conclude only what the evidence carries
//
// Phase 12.1B produced evidence and **zero findings**; Phase 12.1C wires the two
// Kubernetes rules and the generic failure boundary, which is what makes that
// phase's diff the entire behavioural change (ADR 0094 §2.12).
//
// **No transport rule is wired, and that is the shape rather than an omission.**
// The other four composition roots add `transport/dns`, `transport/tcp` and
// `transport/tls`, because their runs measure those stages themselves. A
// Kubernetes run measures none of them: transport belongs to the client library
// (ADR 0093 §2.10), the graph holds no `dns.lookup`, `tcp.connect` or
// `tls.handshake` node, and wiring a rule whose steps cannot appear would be
// three rules that are silent by construction rather than by measurement.
//
// A `SummaryStatus` of OK still means what it has always meant — *no ERROR or
// CRITICAL target-side problem was proven* — and not that the Service has
// backends, that every read ran, or that anything is reachable.
//
// # Errors, and what is not one
//
// An error means the run could not be performed: a refused target, an unreadable
// or prohibited kubeconfig, a credential bound to a different endpoint. **Every
// diagnostic outcome is a report**, including one where the Service does not
// exist, a read was denied, or an enumeration hit a budget.
func DiagnoseKubernetes(ctx context.Context, params KubernetesParams) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return Result{}, err
	}

	startedAt := time.Now()
	acquisition, err := client.Acquire(ctx, client.Params{
		Target:     params.Target,
		Credential: params.Credential,
		Budgets:    params.Budgets,
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	builder := domain.NewGraphBuilder()
	if _, err := adapterkubernetes.Record(builder, acquisition, startedAt); err != nil {
		return Result{}, err
	}
	graph, err := builder.Freeze()
	if err != nil {
		return Result{}, fmt.Errorf("freezing the evidence graph: %w", err)
	}

	// **Incompleteness is the acquisition's own answer, not a scan of the
	// graph.** The other four services derive it from UNKNOWN nodes carrying a
	// local-timeout class, because that is the only shape their probes produce.
	// Kubernetes has a second, more precise shape — an enumeration that stopped
	// at a ceiling — and the acquisition already knows which sets are totals.
	// Re-deriving it from evidence would be a second implementation of a question
	// that has one answer.
	incomplete := acquisition.Incomplete() || ctx.Err() != nil

	// Each rule is wired in under a stable identity; see the note in
	// diagnosePostgres for why the identity is written here rather than exported
	// from the rule's own package.
	registry, err := diagnosis.NewRuleSet().
		// The generic failure boundary, wired first because it is the only rule
		// here that is about the shape of the whole graph rather than about one
		// stage. It restates measured states and infers nothing (ADR 0079), and
		// it is what localizes the API outcomes that deliberately earn no
		// Kubernetes finding of their own — a 401, a 5xx, a timeout, a reset
		// (ADR 0094 §2.8).
		Add("diag/failure-boundary", diagnosis.FailureBoundary).
		// What svcdoctor could obtain: KUBERNETES_SERVICE_NOT_FOUND and
		// KUBERNETES_API_ACCESS_DENIED.
		Add("kubernetes/acquisition", diagnosiskubernetes.Acquisition).
		// What Kubernetes records: KUBERNETES_SERVICE_SELECTS_NO_PODS and
		// KUBERNETES_SERVICE_NO_READY_ENDPOINT.
		Add("kubernetes/backends", diagnosiskubernetes.Backends).
		Freeze()
	if err != nil {
		return Result{}, err
	}

	outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph:      graph,
		Vantage:    params.Vantage,
		Incomplete: incomplete,
	})

	report, err := buildKubernetesReport(
		graph, outcome.Findings(), acquisition, params, startedAt)
	if err != nil {
		return Result{}, err
	}
	// A discarded rule makes the run incomplete; see diagnosePostgres.
	return Result{report: report, incomplete: incomplete || outcome.Failed()}, nil
}

// buildKubernetesReport assembles the canonical report.
func buildKubernetesReport(
	graph domain.Graph, findings []domain.Finding, acquisition client.Result,
	params KubernetesParams, startedAt time.Time,
) (domain.Report, error) {
	service, err := domain.NewServiceID(servicekubernetes.ServiceID)
	if err != nil {
		return domain.Report{}, fmt.Errorf("building service id: %w", err)
	}
	run, err := domain.NewRunMetadata(params.Version, startedAt, time.Since(startedAt), service)
	if err != nil {
		return domain.Report{}, fmt.Errorf("building run metadata: %w", err)
	}
	// The report's target is the Service object, exactly as the evidence subject
	// is. The API server's host and port appear nowhere: they bind the credential
	// and are not this run's identity.
	target, err := domain.NewTarget(acquisition.Target.SubjectRef())
	if err != nil {
		return domain.Report{}, fmt.Errorf("building target: %w", err)
	}
	// **False, and not merely unset.** A Kubernetes run verifies the API server's
	// certificate on every path — `insecure-skip-tls-verify` is refused as a
	// configuration error before anything is sent — so there is no verification
	// this run could have disabled, and saying so is a fact rather than a default
	// (ADR 0060).
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		return domain.Report{}, fmt.Errorf("building report security: %w", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run:      run,
		Target:   target,
		Vantage:  params.Vantage,
		Graph:    graph,
		Findings: findings,
		Security: reportSecurity,
	})
	if err != nil {
		return domain.Report{}, fmt.Errorf("building report: %w", err)
	}
	return report, nil
}
