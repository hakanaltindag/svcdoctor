package run_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// A service-neutral, deterministic runner double.
//
// # Why the scheduler is tested against this rather than against a service
//
// Every rule in this package is about scheduling: order, budgets, cancellation,
// state classification, summary derivation. None of them is about a protocol,
// and testing them through a real adapter would mean a Docker fixture standing
// between a defect and its test — slower, flakier, and unable to express "block
// until I release you" or "complete in this exact order".
//
// The composition that a real service runner performs is proven separately, by
// the four-service integration smoke.
//
// Nothing here is production behaviour. This file is `_test.go`, so it cannot be
// linked into a binary.

// behaviour is what a fake runner does for one target.
type behaviour int

const (
	// behaveSuccess returns a report whose summary status is OK.
	behaveSuccess behaviour = iota

	// behaveProblems returns a report carrying an ERROR finding, which is what a
	// real remote refusal — a rejected credential, a denied virtual host — looks
	// like from the scheduler's side: a completed execution with a diagnostic
	// failure inside it.
	behaveProblems

	// behaveIncomplete returns a report the target's own budget cut short.
	behaveIncomplete

	// behaveError returns an error instead of a report, which is what an
	// invariant failure inside a composition root looks like.
	behaveError

	// behaveBlockUntilReleased waits for the harness to release it.
	behaveBlockUntilReleased

	// behaveBlockUntilCancelled waits for its context and then returns an
	// incomplete report, which is what every composition root does on
	// cancellation: the graph is frozen over whatever was measured.
	behaveBlockUntilCancelled

	// behaveHang ignores cancellation until its own deadline, proving that a
	// worker cannot outlive the smaller of the two budgets.
	behaveHang
)

// fakeRunner is one registered service, driven by a per-target script.
type fakeRunner struct {
	kind string

	// script maps a target id to what should happen. A target with no entry
	// succeeds.
	script map[string]behaviour

	// release gates every behaveBlockUntilReleased target.
	release chan struct{}

	// gate, when set, holds each target until its own channel is closed. It is
	// how a test chooses a completion order rather than racing for one.
	gate map[string]chan struct{}

	mu sync.Mutex
	// startOrder and completionOrder record target ids as they are seen.
	startOrder      []string
	completionOrder []string
	// credentials records the credential each target was handed, so a test can
	// prove two targets naming one reference received two distinct values.
	credentials map[string]security.Credential
	// deadlines records each target's effective deadline.
	deadlines map[string]time.Time
	// stepTimeouts records the step budget each target was configured with, so a
	// test can prove the scheduler passed the frozen value through unchanged.
	stepTimeouts map[string]time.Duration

	// active and maxActive are an independent count of simultaneous runners.
	// They are deliberately atomic and separate from any scheduler state: a
	// concurrency bound inferred from the scheduler's own bookkeeping would
	// prove only that the bookkeeping agrees with itself.
	active    atomic.Int64
	maxActive atomic.Int64
}

func newFakeRunner(kind string) *fakeRunner {
	return &fakeRunner{
		kind:         kind,
		script:       map[string]behaviour{},
		release:      make(chan struct{}),
		credentials:  map[string]security.Credential{},
		deadlines:    map[string]time.Time{},
		stepTimeouts: map[string]time.Duration{},
	}
}

func (f *fakeRunner) Kind() string { return f.kind }

// errFakeExecution is what behaveError returns.
var errFakeExecution = errors.New("the composition root could not perform this run")

func (f *fakeRunner) Run(
	ctx context.Context, target config.Target, credential security.Credential,
) (run.Outcome, error) {
	id := target.ID.String()

	current := f.active.Add(1)
	for {
		peak := f.maxActive.Load()
		if current <= peak || f.maxActive.CompareAndSwap(peak, current) {
			break
		}
	}
	defer f.active.Add(-1)

	f.mu.Lock()
	f.startOrder = append(f.startOrder, id)
	f.credentials[id] = credential
	f.stepTimeouts[id] = target.StepTimeout
	if deadline, ok := ctx.Deadline(); ok {
		f.deadlines[id] = deadline
	}
	behave := f.script[id]
	gate := f.gate[id]
	f.mu.Unlock()

	// A gated target waits before doing anything else, which is how a test picks
	// the order results come back in.
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			f.mu.Lock()
			f.completionOrder = append(f.completionOrder, id)
			f.mu.Unlock()
			return run.Outcome{Report: fakeReport(id, false), Incomplete: true}, nil
		}
	}

	defer func() {
		f.mu.Lock()
		f.completionOrder = append(f.completionOrder, id)
		f.mu.Unlock()
	}()

	switch behave {
	case behaveError:
		return run.Outcome{}, errFakeExecution

	case behaveBlockUntilReleased:
		select {
		case <-f.release:
		case <-ctx.Done():
			return run.Outcome{Report: fakeReport(id, false), Incomplete: true}, nil
		}

	case behaveBlockUntilCancelled:
		<-ctx.Done()
		return run.Outcome{Report: fakeReport(id, false), Incomplete: true}, nil

	case behaveHang:
		// Ignores cancellation. Its own deadline is what stops it, which is the
		// property being proven: a misbehaving target cannot hang the run past
		// the smaller of the two budgets.
		<-ctx.Done()
		return run.Outcome{Report: fakeReport(id, false), Incomplete: true}, nil

	case behaveIncomplete:
		return run.Outcome{Report: fakeReport(id, false), Incomplete: true}, nil

	case behaveProblems:
		return run.Outcome{Report: fakeReport(id, true), Incomplete: false}, nil

	case behaveSuccess:
	}

	return run.Outcome{Report: fakeReport(id, false), Incomplete: false}, nil
}

func (f *fakeRunner) starts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.startOrder...)
}

func (f *fakeRunner) completions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.completionOrder...)
}

func (f *fakeRunner) credentialFor(id string) (security.Credential, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.credentials[id]
	return c, ok
}

func (f *fakeRunner) stepTimeoutFor(id string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stepTimeouts[id]
}

func (f *fakeRunner) deadlineFor(id string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deadlines[id]
	return d, ok
}

// fakeReport builds a minimal valid canonical report.
//
// It is a real domain.Report through the ordinary constructors, not a stub: the
// scheduler folds its summary status into the run summary, and a fake that
// short-circuited that would prove nothing about the fold.
func fakeReport(id string, problems bool) domain.Report {
	report, err := buildReport(id, problems)
	if err != nil {
		panic("fake report: " + err.Error())
	}
	return report
}

func buildReport(id string, problems bool) (domain.Report, error) {
	host := id + ".example.com"
	label := host + ":5432"

	builder := domain.NewGraphBuilder()
	subject, err := domain.NewTargetSubject(label)
	if err != nil {
		return domain.Report{}, err
	}
	// A FAIL node needs a failure class, which the domain enforces. The fake
	// builds a real report through the real constructors precisely so that
	// constraints like this one apply to it too.
	state, failure := domain.StatePass, domain.FailureNone
	if problems {
		state, failure = domain.StateFail, domain.FailureTCPConnectionRefused
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(string(vocabulary.StepTargetRequested) + "/" + label),
		Subject:      subject,
		Layer:        domain.LayerInput,
		Step:         vocabulary.StepTargetRequested,
		State:        state,
		FailureClass: failure,
		StartedAt:    time.Unix(0, 0).UTC(),
		Elapsed:      domain.Unmeasured(),
	})
	if err != nil {
		return domain.Report{}, err
	}
	if err := builder.AddEvidence(evidence); err != nil {
		return domain.Report{}, err
	}
	graph, err := builder.Freeze()
	if err != nil {
		return domain.Report{}, err
	}

	var findings []domain.Finding
	if problems {
		recommendation, err := domain.NewRecommendation("Check the endpoint's credentials")
		if err != nil {
			return domain.Report{}, err
		}
		finding, err := domain.NewFinding(domain.FindingInput{
			Code:            domain.FindingCode("POSTGRES_CREDENTIALS_REJECTED"),
			Kind:            domain.FindingKindConfirmed,
			Severity:        domain.SeverityError,
			Confidence:      domain.ConfidenceHigh,
			Layer:           domain.LayerAuth,
			Subject:         subject,
			Summary:         "The endpoint refused the credential that was presented",
			Detail:          "The endpoint answered, and it declined the credential.",
			EvidenceRefs:    []domain.EvidenceID{evidence.ID()},
			Recommendations: []domain.Recommendation{recommendation},
		})
		if err != nil {
			return domain.Report{}, err
		}
		findings = append(findings, finding)
	}

	runMeta, err := domain.NewRunMetadata("test", time.Unix(0, 0).UTC(), 0, domain.ServiceID("postgres"))
	if err != nil {
		return domain.Report{}, err
	}
	target, err := domain.NewTarget(label)
	if err != nil {
		return domain.Report{}, err
	}
	vantage, err := domain.NewLocalVantage("runner.example.com")
	if err != nil {
		return domain.Report{}, err
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		return domain.Report{}, err
	}

	return domain.NewReport(domain.ReportInput{
		Run:      runMeta,
		Target:   target,
		Vantage:  vantage,
		Graph:    graph,
		Findings: findings,
		Security: reportSecurity,
	})
}

// fakeResolver hands out credentials without touching a filesystem.
//
// It counts calls per target so a test can prove that two targets naming one
// reference produce two independent resolutions, and that a never-started target
// produces none at all.
type fakeResolver struct {
	mu sync.Mutex
	// fail names target ids whose resolution should fail.
	fail map[string]error
	// calls counts CredentialFor per target id.
	calls map[string]int
	// issued records the credential handed to each target.
	issued map[string]security.Credential
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		fail:   map[string]error{},
		calls:  map[string]int{},
		issued: map[string]security.Credential{},
	}
}

func (r *fakeResolver) CredentialFor(
	_ context.Context, target config.Target,
) (security.Credential, error) {
	id := target.ID.String()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[id]++

	if err, failing := r.fail[id]; failing {
		return security.Credential{}, err
	}
	if target.Credentials.Password.IsZero() {
		return security.Credential{}, nil
	}

	endpoint, err := security.NewEndpoint(target.Host, target.Port)
	if err != nil {
		return security.Credential{}, err
	}
	// A distinct secret per target, so a test can prove that two targets naming
	// one reference did not receive one shared object.
	secret := security.NewSecret(fmt.Sprintf("secret-for-%s", id))
	credential, err := security.NewCredential(endpoint, target.Credentials.Username, secret)
	if err != nil {
		return security.Credential{}, err
	}
	r.issued[id] = credential
	return credential, nil
}

func (r *fakeResolver) callCount(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[id]
}

// resolutionError mimics internal/fleet/secret's two-message error.
//
// Error names the reference, which is what stderr needs. SafeMessage does not,
// which is what the canonical report needs. The scheduler must serialize the
// second and never the first (ADR 0074 §4.2).
type resolutionError struct {
	reference string
	reason    string
}

func (e *resolutionError) Error() string {
	return fmt.Sprintf("credential env %s: %s", e.reference, e.reason)
}

func (e *resolutionError) SafeMessage() string {
	return fmt.Sprintf("the credential named by a env reference could not be resolved: %s",
		e.reason)
}

// harness builds a run from a compact scenario description.
type harness struct {
	t        *testing.T
	runner   *fakeRunner
	resolver *fakeResolver
	cfg      config.Config
}

// newHarness builds n targets named a, b, c, ... each with a credential
// reference, and registers one fake service for all of them.
func newHarness(t *testing.T, ids ...string) *harness {
	t.Helper()

	targets := make([]config.Target, 0, len(ids))
	for _, id := range ids {
		targets = append(targets, testTarget(t, id))
	}

	return &harness{
		t:        t,
		runner:   newFakeRunner(testServiceKind),
		resolver: newFakeResolver(),
		cfg: config.Config{
			Version: config.Version,
			Run:     config.Run{Concurrency: 1},
			Targets: targets,
		},
	}
}

// testServiceKind is the fake service's registration key.
//
// A neutral name rather than "postgres": the scheduler must not behave
// differently for any particular service, and a fake wearing a real service's
// name would let a service-specific branch pass this whole suite.
const testServiceKind = "testsvc"

func testTarget(t *testing.T, id string) config.Target {
	t.Helper()
	targetID, err := config.NewTargetID(id)
	if err != nil {
		t.Fatalf("NewTargetID(%q): %v", id, err)
	}
	return config.Target{
		ID:          targetID,
		Service:     testServiceKind,
		Host:        id + ".example.com",
		Port:        5432,
		Timeout:     30 * time.Second,
		StepTimeout: 10 * time.Second,
	}
}

func (h *harness) concurrency(n int) *harness {
	h.cfg.Run.Concurrency = n
	return h
}

func (h *harness) runTimeout(d time.Duration) *harness {
	h.cfg.Run.Timeout = d
	return h
}

func (h *harness) targetTimeout(id string, d time.Duration) *harness {
	for i := range h.cfg.Targets {
		if h.cfg.Targets[i].ID.String() == id {
			h.cfg.Targets[i].Timeout = d
		}
	}
	return h
}

func (h *harness) behave(id string, b behaviour) *harness {
	h.runner.script[id] = b
	return h
}

func (h *harness) resolveFails(id string, err error) *harness {
	h.resolver.fail[id] = err
	return h
}

// withCredential gives a target a credential reference, so the resolver issues
// one for it.
func (h *harness) withCredential(id, envName string) *harness {
	for i := range h.cfg.Targets {
		if h.cfg.Targets[i].ID.String() != id {
			continue
		}
		cfg, err := config.Load([]byte(fmt.Sprintf(
			"version: 1\ntargets:\n  - id: %s\n    type: testsvc\n    host: h.example.com\n"+
				"    credentials:\n      username: u\n      password:\n        env: %s\n",
			id, envName)), "harness.yaml", credentialRegistry(h.t))
		if err != nil {
			h.t.Fatalf("building a credential reference: %v", err)
		}
		h.cfg.Targets[i].Credentials = cfg.Targets[0].Credentials
	}
	return h
}

// credentialRegistry registers the fake kind so the harness can borrow the real
// config decoder to build a real Reference. Nothing in this package can
// construct one directly, which is the point of ADR 0072's closed union.
func credentialRegistry(t *testing.T) *config.Registry {
	t.Helper()
	registry, err := config.NewRegistry(neutralFactory{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return registry
}

type neutralFactory struct{}

func (neutralFactory) Kind() string        { return testServiceKind }
func (neutralFactory) DefaultPort() uint16 { return 5432 }
func (neutralFactory) Decode(*config.ServiceNode, config.Common) (config.ServiceConfig, error) {
	return neutralConfig{}, nil
}

type neutralConfig struct{}

func (neutralConfig) Kind() string { return testServiceKind }

func (h *harness) params() run.Params {
	h.t.Helper()
	registry, err := run.NewRegistry(h.runner)
	if err != nil {
		h.t.Fatalf("run.NewRegistry: %v", err)
	}
	return run.Params{
		Config:   h.cfg,
		Registry: registry,
		Resolver: h.resolver,
		Version:  "test",
	}
}

func (h *harness) execute(ctx context.Context) (domain.RunReport, error) {
	h.t.Helper()
	return run.Execute(ctx, h.params())
}

func (h *harness) executeSequential(ctx context.Context) (domain.RunReport, error) {
	h.t.Helper()
	return run.ExecuteSequential(ctx, h.params())
}
