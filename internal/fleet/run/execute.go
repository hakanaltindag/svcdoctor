package run

import (
	"context"
	"errors"
	"sync"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// ExecuteSequential runs every target one after another and is the reference
// semantics.
//
// # Why a second executor exists at all
//
// Every rule this package implements — how a budget composes, when a target is
// CANCELLED rather than COMPLETED, what a never-started target carries, what the
// summary counts — is easier to state and far easier to verify without
// goroutines in the way. So it is stated here first, and Execute is required to
// agree with it: TestConcurrencyOneMatchesTheSequentialReference compares their
// structured output on the same scenario, and the two must be identical.
//
// A semantics that only holds when nothing runs in parallel is not a semantics,
// and a concurrent implementation with no sequential reference has nothing to be
// wrong against.
//
// It is production-callable and not a test fixture: `concurrency: 1` is a
// supported configuration, and an operator who chooses it gets this.
func ExecuteSequential(ctx context.Context, params Params) (domain.RunReport, error) {
	return execute(ctx, params, 1)
}

// Execute runs every target through a bounded worker pool.
//
// The pool size is the configuration's resolved concurrency. It bounds targets
// in flight and **not** sockets: one target may itself open a connection per
// resolved address, and Kafka additionally sweeps its advertised brokers.
// ADR 0073 section 10.1 declines a global probe semaphore in this phase, and
// this comment is the honest statement of what the number does and does not
// mean.
func Execute(ctx context.Context, params Params) (domain.RunReport, error) {
	if err := params.validate(); err != nil {
		return domain.RunReport{}, err
	}
	return execute(ctx, params, params.Config.Run.Concurrency)
}

// execute is the whole scheduler, shared by both entry points.
//
// The two differ only in worker count, which is what makes their agreement a
// property of one implementation rather than a coincidence between two.
func execute(ctx context.Context, params Params, workers int) (domain.RunReport, error) {
	if err := params.validate(); err != nil {
		return domain.RunReport{}, err
	}
	if ctx == nil {
		return domain.RunReport{}, errors.New("run: context must not be nil")
	}

	targets := params.Config.Targets
	startedAt := params.now()

	// The run budget, and the parent of every target context.
	//
	// **Deriving each target from this is what makes "the earlier deadline
	// always wins" structural** rather than a comparison somebody has to write
	// correctly. A target that starts twenty seconds before the run deadline
	// gets twenty seconds, not its full budget, because context.WithTimeout on a
	// parent that is already closer never extends it (ADR 0073 §4.1).
	runCtx := ctx
	if timeout := params.Config.Run.Timeout; timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Results live in an index-addressed slice, written exactly once by whichever
	// worker owns that index. There is no channel of results to reorder, no map
	// to iterate and no sort — which is how declared configuration order survives
	// concurrency by construction rather than by being restored afterwards
	// (ADR 0073 §6.2).
	results := make([]domain.TargetResult, len(targets))

	e := &executor{params: params, runCtx: runCtx, results: results}

	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range next {
				e.runOne(index)
			}
		}()
	}

	// The dispatcher stops offering work the moment the run context is done.
	// Targets it never offered are never started, and nothing about them is
	// invented.
	dispatch(runCtx, next, len(targets))

	// Unconditional, and bounded without a new timer: every started target runs
	// under a context derived from runCtx and additionally capped by its own
	// budget, so a worker cannot outlive the smaller of the two. ADR 0073 §8
	// declines a separate cleanup budget for exactly this reason — a second
	// number would create a case where the two disagree.
	wg.Wait()

	// Whatever was never dispatched, or was dispatched and never reached,
	// becomes NOT_STARTED here. This runs after Wait, so it cannot race a worker
	// that was writing the same index.
	for i, target := range targets {
		if !results[i].IsZero() {
			continue
		}
		result, err := domain.NotStartedTarget(target.ID.String(), serviceID(target))
		if err != nil {
			return domain.RunReport{}, err
		}
		results[i] = result
	}

	report, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: params.Version,
		StartedAt:        startedAt,
		Duration:         params.now().Sub(startedAt),
		Concurrency:      workers,
		OutputMode:       domain.OutputModeLocalFull,
		StoppedReason:    stoppedReason(ctx, runCtx, results),
		Targets:          results,
	})
	if err != nil {
		return domain.RunReport{}, err
	}
	return report, nil
}

// dispatch offers each index in declared order until the run context is done.
func dispatch(runCtx context.Context, next chan<- int, count int) {
	defer close(next)
	for i := range count {
		select {
		case <-runCtx.Done():
			return
		case next <- i:
		}
	}
}

// executor holds one run's shared, immutable state.
//
// The only mutable thing is the results slice, and each index is written by
// exactly one worker exactly once. There is no shared counter, no accumulator
// and no map, so there is nothing for two workers to contend over.
type executor struct {
	params  Params
	runCtx  context.Context
	results []domain.TargetResult
}

// runOne executes a single target and records its result.
//
// The pipeline is ADR 0074 section 4's, in order:
//
//	credential resolution   -> EXECUTION_FAILED on failure, nothing dialled
//	target budget           -> derived from the run's, never from the root
//	the service runner      -> the existing composition root
//	classification          -> COMPLETED, CANCELLED or EXECUTION_FAILED
func (e *executor) runOne(index int) {
	target := e.params.Config.Targets[index]
	id := target.ID.String()
	service := serviceID(target)

	// A target the dispatcher offered just as the run ended must not be started.
	// Without this a run whose budget expired could still spend a connection.
	if e.runCtx.Err() != nil {
		e.results[index] = mustNotStarted(id, service)
		return
	}

	// Resolution happens per target, immediately before that target executes, so
	// at most `concurrency` secrets are ever alive at once (ADR 0072 §5.2). The
	// credential goes out of scope when this function returns.
	credential, err := e.params.Resolver.CredentialFor(e.runCtx, target)
	if err != nil {
		// **This is not an authentication rejection.** No byte reached the
		// endpoint, so no service finding may describe it, and no DNS, TCP, TLS
		// or authentication evidence is fabricated. The message is the
		// resolver's, which names the reference and never its value.
		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		return
	}

	targetCtx, cancel := context.WithTimeout(e.runCtx, target.Timeout)
	defer cancel()

	runner, _ := e.params.Registry.lookup(target.Service)
	outcome, err := runner.Run(targetCtx, target, credential)
	if err != nil {
		e.results[index] = mustFailed(id, service, domain.ExecutionErrorInternal, err.Error())
		return
	}

	e.results[index] = e.classify(id, service, outcome)
}

// classify decides between COMPLETED and CANCELLED.
//
// # The distinction is "did the run end this", not "was it cut short"
//
// A target whose own timeout or step budget expired is **COMPLETED**: it ran to
// the end of its own budget and produced its own truthful report, which says so
// through Incomplete. That is the report's business, and orchestration has
// nothing to add.
//
// CANCELLED is reserved for the run ending a target that had not finished — the
// run deadline or a signal. Both conditions are required. A target that
// completed fully in the instant before a cancellation landed is COMPLETED,
// because it completed; testing the run context alone would relabel it on a race
// that changed nothing about what was measured.
//
// The residual ambiguity is real and small: a target that was still running when
// the run was cancelled *and* would have been incomplete anyway is attributed to
// the run. Its report carries what actually happened either way.
func (e *executor) classify(id string, service domain.ServiceID, outcome Outcome) domain.TargetResult {
	if e.runCtx.Err() != nil && outcome.Incomplete {
		result, err := domain.CancelledTarget(id, service, outcome.Report, outcome.Incomplete)
		if err != nil {
			return mustFailed(id, service, domain.ExecutionErrorInternal, err.Error())
		}
		return result
	}
	result, err := domain.CompletedTarget(id, service, outcome.Report, outcome.Incomplete)
	if err != nil {
		return mustFailed(id, service, domain.ExecutionErrorInternal, err.Error())
	}
	return result
}

// stoppedReason records once why scheduling did not reach every target.
//
// ADR 0074 section 4.3 keeps this at run level rather than on each queued
// target: a run stops for one reason, and copying it onto four hundred results
// would be four hundred copies of one fact.
func stoppedReason(
	ctx, runCtx context.Context, results []domain.TargetResult,
) domain.StoppedReason {
	incompleteScheduling := false
	for _, result := range results {
		if result.ExecutionState() == domain.ExecutionStateNotStarted ||
			result.ExecutionState() == domain.ExecutionStateCancelled {
			incompleteScheduling = true
			break
		}
	}
	if !incompleteScheduling {
		return domain.StoppedReasonNone
	}

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		// The caller's own deadline, which is a budget rather than an interrupt.
		return domain.StoppedReasonRunBudgetExhausted
	case ctx.Err() != nil:
		return domain.StoppedReasonCancelled
	case runCtx.Err() != nil:
		return domain.StoppedReasonRunBudgetExhausted
	default:
		// Reachable when a target was cancelled by something other than the run,
		// which no current path produces. Naming it None is the honest answer:
		// scheduling was not what stopped.
		return domain.StoppedReasonNone
	}
}

// safeMessenger is an error that knows which of its two messages is safe to
// serialize.
//
// internal/fleet/secret's ResolutionError implements it. The interface lives
// here rather than there so that the scheduler needs no import of the resolver's
// package to ask the question.
type safeMessenger interface {
	SafeMessage() string
}

// safeMessage extracts a message that may reach a canonical report.
//
// # It fails closed, and that is the whole design
//
// An error that does not offer a safe form gets a fixed phrase rather than its
// own text. ADR 0074 section 4.2 keeps a credential reference name, a file path
// and an environment variable name out of the report, and the resolver's
// ordinary Error() carries the first two deliberately — it is written for
// stderr.
//
// Defaulting to err.Error() here would mean every future error type leaks by
// omission: someone adds a resolver source, forgets SafeMessage, and a path
// appears in a document people paste into tickets. Defaulting to a generic
// sentence means they lose detail instead, which is recoverable.
func safeMessage(err error) string {
	var messenger safeMessenger
	if errors.As(err, &messenger) {
		return messenger.SafeMessage()
	}
	return "the credential could not be resolved"
}

// serviceID converts a validated target's service kind.
//
// The kind came through config validation against a registered factory, and
// domain.ServiceID's grammar is a lowercase segment — which every registered
// kind already satisfies. A failure here would be a programming error in a
// service package, and it surfaces as an execution failure rather than a panic.
func serviceID(target config.Target) domain.ServiceID {
	id, err := domain.NewServiceID(target.Service)
	if err != nil {
		return domain.ServiceID("")
	}
	return id
}

// mustNotStarted and mustFailed fold a constructor error that cannot occur.
//
// Both constructors reject only an empty target id, an invalid service id, an
// invalid error class or an empty message — and every caller here supplies
// values that came through configuration validation or from a constant. The
// fallback keeps a defect visible as a result rather than as a panic in a
// worker goroutine, which would take the whole run down and lose every other
// target's report.
func mustNotStarted(id string, service domain.ServiceID) domain.TargetResult {
	result, err := domain.NotStartedTarget(id, service)
	if err != nil {
		return fallbackFailure(id, service, err)
	}
	return result
}

func mustFailed(
	id string, service domain.ServiceID, class domain.ExecutionErrorClass, message string,
) domain.TargetResult {
	if message == "" {
		message = "the target could not be executed"
	}
	result, err := domain.FailedTarget(id, service, class, message)
	if err != nil {
		return fallbackFailure(id, service, err)
	}
	return result
}

// fallbackFailure is the last resort when even FailedTarget refuses.
func fallbackFailure(id string, service domain.ServiceID, cause error) domain.TargetResult {
	if id == "" {
		id = "unknown"
	}
	if !service.Valid() {
		service = domain.ServiceID("unknown")
	}
	result, err := domain.FailedTarget(id, service, domain.ExecutionErrorInternal, cause.Error())
	if err != nil {
		// Unreachable: id and service have just been made valid, the class is a
		// constant and the message is non-empty.
		return domain.TargetResult{}
	}
	return result
}

// unusedCredential exists to state, in code that the compiler checks, that this
// package holds a credential and never opens one.
//
// security.Credential has no plain secret accessor: reading it requires
// SecretFor with the endpoint it is about to be used against, and that call
// lives in the adapter. The scheduler passes the value through, which is why
// this package can import internal/security without being able to misuse it.
var _ = func(c security.Credential) security.Credential { return c }
