package config

import (
	"fmt"
	"time"
)

// Execution defaults, inherited from the four leaf commands so that a target
// written with no budgets behaves exactly as the equivalent single-target
// invocation does today (ADR 0073 §4.2). That equivalence is the property that
// makes a fleet file a faithful description of four invocations rather than an
// approximation of them.
const (
	// DefaultTargetTimeout is every leaf command's `--timeout` default.
	DefaultTargetTimeout = 30 * time.Second

	// DefaultStepTimeout is every leaf command's `--step-timeout` default.
	DefaultStepTimeout = 10 * time.Second

	// DefaultConcurrency is how many targets run at once when nothing says
	// otherwise. ADR 0073 §3.1: a fixed number rather than one derived from the
	// CPU count, because concurrency here is a safety control and the load a
	// command puts on shared infrastructure must not depend on the machine it
	// was typed on.
	DefaultConcurrency = 4

	// MaxConcurrency is the ceiling. ADR 0073 §3.2 derives it: a container's
	// default descriptor soft limit is commonly 1024, a pessimistic per-target
	// peak is 32 sockets, and 16 × 32 leaves half of that limit unused.
	MaxConcurrency = 16
)

// document is the wire shape of a configuration file.
//
// It is unexported because it is the *decoded* form and not the validated one.
// Callers receive a Config, which exists only after every check has run — so
// there is no way to hold a configuration that was parsed but not validated.
type document struct {
	Version int           `yaml:"version"`
	Run     runSection    `yaml:"run"`
	Targets []targetBlock `yaml:"targets"`
}

// runSection is the run-wide block.
type runSection struct {
	// Concurrency is how many targets run at once. Nil means the default.
	//
	// A pointer because `concurrency: 0` is a value the operator typed and must
	// be refused, while an absent key means "use the default". ADR 0073 §3.3:
	// zero has two plausible readings — unlimited and default — and one of them
	// opens every connection at once.
	Concurrency *int `yaml:"concurrency"`

	// Timeout bounds the whole run. Zero means unset, which is the default:
	// ADR 0073 §4.3 declines a run-level default because it would silently
	// decide how large a file may be.
	Timeout Duration `yaml:"timeout"`
}

// targetBlock is the wire shape of one target.
//
// # The envelope, and what is deliberately not in it
//
// There is no `database`, no `vhost`, no `sasl_mechanism` and no field belonging
// to any service. ADR 0071 section 6.2 rejected that shape: one struct carrying
// every service's fields makes per-service unknown-field rejection impossible,
// so `vhost` on a PostgreSQL target would have to be accepted. Everything
// service-owned lives under Config and is decoded by that service.
type targetBlock struct {
	ID   TargetID `yaml:"id"`
	Type string   `yaml:"type"`

	// Host and Port are the logical endpoint, and this pair is the credential
	// authority boundary. All four app.*Params document it in near-identical
	// words, and the binding must be constructed once or it can drift per
	// service (ADR 0071 §7.2).
	Host string `yaml:"host"`

	// Port is a pointer so that an explicit `port: 0` is distinguishable from an
	// absent key. Absent takes the service's default; zero is refused, because
	// security.NewEndpoint refuses it and silently substituting 5432 for a port
	// the operator wrote would diagnose an endpoint they did not name.
	Port *int `yaml:"port"`

	Timeout     Duration `yaml:"timeout"`
	StepTimeout Duration `yaml:"step_timeout"`

	TLS         TLS         `yaml:"tls"`
	Credentials Credentials `yaml:"credentials"`

	// Config is the service-owned subtree, held opaquely.
	Config ServiceNode `yaml:"config"`
}

// Target is one validated target.
//
// # It holds no secret and no resolved value
//
// Credentials.Password is a Reference, which has two string fields and both are
// names. There is no field on this type, or reachable from it, that a secret
// value could be assigned to — which is what makes "the validated configuration
// retains no secret" a property of the types rather than a rule someone follows
// (ADR 0072 §5, and TestAValidatedConfigHoldsNoSecretBearingField).
type Target struct {
	// ID is unique within the configuration.
	ID TargetID

	// Service is the registered service kind.
	Service string

	// Host and Port are the logical endpoint. Port is resolved: it is the
	// operator's value, or the service's default when none was written.
	Host string
	Port uint16

	// Timeout and StepTimeout are resolved, never zero.
	Timeout     time.Duration
	StepTimeout time.Duration

	// TLS is the transport-encryption plan as written.
	TLS TLS

	// Credentials is the identity and the credential *reference*.
	Credentials Credentials

	// Config is the service's own validated configuration.
	Config ServiceConfig
}

// Run is the validated run-wide block.
type Run struct {
	// Concurrency is resolved and always within [1, MaxConcurrency].
	Concurrency int

	// Timeout bounds the whole run, or is zero when the operator set none.
	Timeout time.Duration
}

// Config is a validated configuration.
//
// # Targets are a slice, and that is structural rather than incidental
//
// ADR 0073 section 6.2 requires that report order is declared configuration
// order and that worker completion order can never reach the output. Holding
// targets in a slice from decode through execution to serialization is what
// makes "map iteration changed the report order" not a bug that can be fixed but
// a program that cannot be written. Nothing in this package sorts them.
type Config struct {
	// Version is the configuration version, always Version.
	Version int

	// Run is the run-wide block, resolved.
	Run Run

	// Targets are in declared order.
	Targets []Target
}

// TargetIDs returns the identifiers in declared order.
//
// A helper for tests and for the future runner, so neither has to reach into the
// slice and neither is tempted to build a map on the way.
func (c Config) TargetIDs() []string {
	ids := make([]string, 0, len(c.Targets))
	for _, target := range c.Targets {
		ids = append(ids, target.ID.String())
	}
	return ids
}

// References returns every credential reference in declared order.
//
// This is what the preflight in internal/fleet/secret walks. It returns
// references and never values, because that is all a Config has.
func (c Config) References() []Reference {
	refs := make([]Reference, 0, len(c.Targets))
	for _, target := range c.Targets {
		if !target.Credentials.Password.IsZero() {
			refs = append(refs, target.Credentials.Password)
		}
	}
	return refs
}

// validate checks the run block.
func (r runSection) validate(targets []Target) (Run, error) {
	out := Run{Concurrency: DefaultConcurrency, Timeout: r.Timeout.Duration()}

	if r.Concurrency != nil {
		switch value := *r.Concurrency; {
		case value == 0:
			return Run{}, newError(CategoryInvalidField,
				"run.concurrency 0 is not a value; it is refused rather than read as "+
					"\"unlimited\" or as \"use the default\", because one of those two "+
					"readings opens every connection at once").at("run.concurrency")
		case value < 0:
			return Run{}, newError(CategoryInvalidField, fmt.Sprintf(
				"run.concurrency %d must be between 1 and %d", value, MaxConcurrency)).
				at("run.concurrency")
		case value > MaxConcurrency:
			return Run{}, newError(CategoryInvalidField, fmt.Sprintf(
				"run.concurrency %d is above the maximum of %d; the ceiling is what bounds "+
					"total sockets, because one target may itself open one connection per "+
					"resolved address", value, MaxConcurrency)).at("run.concurrency")
		default:
			out.Concurrency = value
		}
	}

	if out.Timeout < 0 {
		return Run{}, newError(CategoryInvalidField, fmt.Sprintf(
			"run.timeout %s must not be negative", out.Timeout)).at("run.timeout")
	}

	// ADR 0073 §4.4: a run budget below the largest target budget guarantees
	// that every target is cut short by a configuration that looks deliberate.
	if out.Timeout > 0 {
		for _, target := range targets {
			if target.Timeout > out.Timeout {
				return Run{}, newError(CategoryInvalidField, fmt.Sprintf(
					"run.timeout %s is below the %s timeout of target %q, so that target "+
						"could never complete", out.Timeout, target.Timeout, target.ID)).
					at("run.timeout")
			}
		}
	}

	return out, nil
}
