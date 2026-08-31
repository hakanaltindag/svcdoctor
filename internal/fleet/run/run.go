// Package run schedules existing diagnoses. It performs none of them.
//
// It is the last clause of the architectural invariant:
//
//	Probes collect facts.
//	Adapters understand protocols.
//	Diagnosis correlates evidence.
//	Renderers explain results.
//	Multi-target orchestration schedules existing diagnoses.
//
// # What it owns
//
// Scheduling, the execution lifecycle, bounded concurrency, the run budget,
// target lifecycle state, aggregation and cancellation propagation.
//
// # What it must not do, and cannot
//
// It performs no protocol diagnosis, reads no evidence to derive a finding,
// imports no adapter, no wire package, no diagnosis package and no probe, calls
// neither security.Reveal nor Credential.SecretFor, reads no environment
// variable and no file, and parses no YAML. Each of those is a structural guard
// in test/security/fleet_run_boundary_test.go rather than a convention.
//
// It also names no service. A target's kind selects a registered Runner, and
// adding a fifth service requires no edit here at all — which is the property
// ADR 0071 section 6.3 asked for and the reason there is no switch anywhere in
// this package.
//
// # Two executors, on purpose
//
// ExecuteSequential is the reference: one target after another, no goroutine,
// no channel. Execute is the production path and is bounded-concurrent. The two
// are required to agree, and TestConcurrencyOneMatchesTheSequentialReference
// pins that — a semantics that only holds when nothing is running in parallel is
// not a semantics.
package run

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// ErrRun reports that a run could not be performed at all.
//
// It means no aggregate exists — a nil registry, a target whose service is not
// registered, an invalid parameter. It is **not** how a target's own failure is
// reported: that is a TargetResult, and the run still produces a report.
var ErrRun = errors.New("run failed")

// Outcome is what one service runner produced.
//
// It is app.Result's two values, restated here so this package does not import
// internal/app — which would pull every adapter, probe and diagnosis package
// into the scheduler's build graph and make the import guards unenforceable.
type Outcome struct {
	// Report is the canonical LOCAL_FULL report for this target.
	Report domain.Report

	// Incomplete is the run's own Result.Incomplete(): whether svcdoctor's
	// execution limit stopped it short of what it set out to measure.
	Incomplete bool
}

// Runner executes one target's diagnosis.
//
// # It is service-neutral by construction
//
// The scheduler holds a Runner and knows nothing else about the service. A
// concrete implementation lives beside that service's configuration type and
// delegates to its existing composition root — app.DiagnosePostgres and the
// other three — which is what keeps credential authority, connection ownership
// and the diagnosis boundary exactly where they already are.
//
// A Runner receives a credential that is already bound to its target's own
// endpoint. It does not resolve one, and the scheduler does not reveal one.
type Runner interface {
	// Kind is the target `type` this runner serves. It is the registration key.
	Kind() string

	// Run performs one diagnosis and returns its report.
	//
	// The context carries the target's effective deadline, already composed from
	// the run's. An implementation passes it down and does not replace it.
	//
	// An error means the run could not be performed — unusable input, or an
	// invariant failure. **Every diagnostic outcome is a report**, including one
	// where nothing connected or the credential was rejected.
	Run(ctx context.Context, target config.Target, credential security.Credential) (Outcome, error)
}

// Resolver turns a target's credential reference into a bound credential.
//
// An interface rather than a concrete type so that this package does not import
// internal/fleet/secret, and so a test can supply a resolver that fails on
// demand without a filesystem. *secret.Resolver satisfies it structurally.
//
// The scheduler calls it once per target, immediately before that target runs.
// It never calls it twice for one target, never holds what it returns beyond
// that target's execution, and never passes one target's result to another.
type Resolver interface {
	CredentialFor(ctx context.Context, target config.Target) (security.Credential, error)
}

// Registry maps a service kind to its runner.
//
// The same discipline as config.Registry, for the same reason: explicit
// registration at one composition point, no init(), no reflection, no global
// mutable state. A second Registry with different runners is an ordinary value,
// which is what makes the scheduler testable without a network.
type Registry struct {
	runners map[string]Runner
	kinds   []string
}

// NewRegistry builds a runner registry from an explicit list.
func NewRegistry(runners ...Runner) (*Registry, error) {
	r := &Registry{runners: make(map[string]Runner, len(runners))}
	for _, runner := range runners {
		if runner == nil {
			return nil, fmt.Errorf("%w: a nil runner was registered", ErrRun)
		}
		kind := runner.Kind()
		if kind == "" {
			return nil, fmt.Errorf("%w: a runner registered an empty kind", ErrRun)
		}
		if _, exists := r.runners[kind]; exists {
			return nil, fmt.Errorf("%w: service kind %q is registered twice", ErrRun, kind)
		}
		r.runners[kind] = runner
		r.kinds = append(r.kinds, kind)
	}
	slices.Sort(r.kinds)
	return r, nil
}

// Kinds returns every registered kind, in a stable order.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.kinds)
}

// lookup returns the runner for kind.
func (r *Registry) lookup(kind string) (Runner, bool) {
	if r == nil {
		return nil, false
	}
	runner, ok := r.runners[kind]
	return runner, ok
}

// Params describes one multi-target run.
type Params struct {
	// Config is the validated configuration. Its Run block already carries the
	// resolved concurrency and run timeout, with any CLI override applied by the
	// command before this is called — so precedence is decided once, above, and
	// this package reads one number.
	Config config.Config

	// Registry maps each target's kind to its runner. Required.
	Registry *Registry

	// Resolver obtains each target's credential. Required.
	Resolver Resolver

	// Version is svcdoctor's own version, recorded in the aggregate.
	Version string

	// Now is the clock, defaulting to time.Now. It exists so a test can pin the
	// run's recorded start without waiting, and for nothing else: no scheduling
	// decision reads it, and every deadline comes from a context.
	Now func() time.Time
}

func (p Params) validate() error {
	switch {
	case p.Registry == nil:
		return fmt.Errorf("%w: no runner registry was supplied", ErrRun)
	case p.Resolver == nil:
		return fmt.Errorf("%w: no credential resolver was supplied", ErrRun)
	case p.Version == "":
		return fmt.Errorf("%w: version must not be empty", ErrRun)
	case len(p.Config.Targets) == 0:
		return fmt.Errorf("%w: the configuration declares no targets", ErrRun)
	case p.Config.Run.Concurrency < 1:
		return fmt.Errorf("%w: concurrency %d must be at least 1",
			ErrRun, p.Config.Run.Concurrency)
	case p.Config.Run.Concurrency > config.MaxConcurrency:
		return fmt.Errorf("%w: concurrency %d is above the maximum of %d",
			ErrRun, p.Config.Run.Concurrency, config.MaxConcurrency)
	}

	// Every target must have a runner before anything executes. A run that
	// discovered an unregistered service halfway through would have spent
	// connections on a run it cannot finish, which is the partial execution
	// ADR 0074 section 9 exists to prevent.
	for _, target := range p.Config.Targets {
		if _, ok := p.Registry.lookup(target.Service); !ok {
			return fmt.Errorf("%w: target %q names service %q, which has no registered runner "+
				"(registered: %s)", ErrRun, target.ID, target.Service,
				strings.Join(p.Registry.Kinds(), ", "))
		}
	}
	return nil
}

func (p Params) now() time.Time {
	if p.Now == nil {
		return time.Now()
	}
	return p.Now()
}
