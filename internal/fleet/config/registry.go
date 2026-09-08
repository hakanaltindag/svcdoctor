package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// ServiceConfig is one service's validated, typed configuration.
//
// It is deliberately almost empty. The generic core never reads a service's
// fields — it holds the value, keeps it in declared order, and in Phase 9.1B
// hands it to the runner. Everything the core needs to know about a service is
// on its Factory.
//
// A concrete type per service, never a shared struct and never a map: ADR 0071
// section 6.2 rejected the single global struct because it makes per-service
// unknown-field rejection impossible, and section 6.1 rejects map[string]any
// because decoding into it re-enables YAML's implicit typing.
type ServiceConfig interface {
	// Kind returns the service this configuration belongs to. It exists so a
	// test, a renderer or the future runner can attribute a value without a type
	// switch in the generic core.
	Kind() string
}

// Common is the generic part of a target, passed to a service's validator.
//
// # Why a service sees the generic fields at all
//
// ADR 0071 section 7.1's second clause: a field is generic when its semantics
// are identical across services, and where the semantics match but the valid
// *range* does not, the field stays generic and its validation moves to the
// service. RabbitMQ is the measured instance — its step timeout must exceed
// three seconds because several broker refusal paths hold the socket open for
// exactly that long, and a shorter budget reports the broker's deliberate delay
// as svcdoctor's own deadline expiring (ADR 0070 §8). PostgreSQL is the other:
// it requires an identity even when no password is configured, because the
// startup message has no anonymous form.
//
// Neither service could enforce its rule without seeing the generic value, and
// putting either rule in the core would make the core know about services.
type Common struct {
	ID          TargetID
	Host        string
	Port        uint16
	Timeout     time.Duration
	StepTimeout time.Duration
	TLS         TLS
	Credentials Credentials

	// StepTimeoutDeclared says whether the target **wrote** `step_timeout`, as
	// opposed to receiving the default.
	//
	// # Why the resolved value cannot answer it
	//
	// StepTimeout is never zero: an absent key becomes DefaultStepTimeout, which
	// is what every consumer wants. So a service cannot tell an operator's "10s"
	// from silence, and one service needs to — for the reason `Port` is a
	// pointer in the schema and for no other.
	//
	// # Which service, and why it is not a special case
	//
	// A Kubernetes run has no per-step budget: three requests run under one
	// deadline, `app.KubernetesParams` carries no such field, and the runner
	// passes none. A written `step_timeout` there is therefore **inert**, and
	// ADR 0060's discipline is that an inert input is refused rather than
	// accepted, because an operator who wrote it believes it did something.
	// Phase 12.1C.1 refused `--step-timeout` on the leaf command for exactly
	// that reason; this is the same refusal on the other entry point, which
	// Phase 12.1D found still missing.
	//
	// Four services ignore this field. Nothing about their behaviour changes,
	// and a sixth service that has steps ignores it too.
	StepTimeoutDeclared bool
}

// Factory is what a service registers so the generic core can handle its targets.
//
// Three small methods. None of them opens a connection, resolves a name, reads
// an environment variable or resolves a credential: a factory turns bytes into a
// validated value.
//
// # It may read a file the target itself names, and one service does
//
// This comment read *"none of them performs I/O"* from Phase 9.1A until Phase
// 12.1B, when a service arrived whose authority is a file. A Kubernetes target
// names a kubeconfig, and three things follow from that file: whether the target
// is usable at all, which cluster it reads, and — critically — whether it carries
// a construct svcdoctor refuses, such as an `exec` credential plugin.
//
// Deferring those to execution would make a kubeconfig that makes svcdoctor run a
// local program into *one target's execution failure at exit 4* rather than a
// configuration error at exit 2 with nothing dialled. That is the same defect
// Phase 9.1C found in the credential path and fixed for the same reason, so the
// sentence is amended rather than the rule bent around.
//
// The boundary that did not move: **internal/fleet/config still opens exactly one
// file, the configuration document.** A service factory lives in its own package
// and may read what its own target names — which is what internal/fleet/services
// already does at preflight, where trustsource.Load reads `tls.ca_file`.
type Factory interface {
	// Kind is the value of a target's `type` field. It is the registration key
	// and must be unique.
	Kind() string

	// DefaultPort is used when a target names no port.
	//
	// It is service-owned rather than generic because 5432, 9092, 6379 and 5672
	// are four different answers. Nothing infers a service *from* a port —
	// ADR 0011 refuses that — this is the other direction, which is safe: the
	// operator already said which service it is.
	DefaultPort() uint16

	// Decode turns the target's `config:` subtree into a typed value and
	// validates it together with the generic fields.
	//
	// It receives an opaque ServiceNode rather than a YAML node, which is what
	// keeps the YAML dependency inside internal/fleet/config (ADR 0071 §3.3).
	Decode(node *ServiceNode, common Common) (ServiceConfig, error)
}

// EndpointDeriver is implemented by a factory whose targets name no host.
//
// # Why an optional interface rather than a fifth Factory method
//
// Four of the five services registered today are asked about an endpoint an
// operator typed, and for them `host` is the target's most important field. One
// is not: its endpoint is **derived** from material the target already names, so
// writing a host there would be a value nobody reads — and ADR 0060's discipline
// is that an inert input is refused rather than accepted, because an operator
// who wrote it believes it did something.
//
// Putting the question on every Factory would make four services answer a
// question only one has, and would mean editing four files to add a fifth
// service — which is the coupling the registry exists to remove. An optional
// interface asks it of the one service that has an answer, stays service-neutral
// here, and needs no edit anywhere else.
//
// # What the generic contract still requires
//
// **The host requirement is satisfied, not relaxed.** A derived endpoint is
// validated by exactly the same checks a written one is, and a factory that
// derives nothing usable fails its target. What changes is where the value comes
// from, and nothing downstream — preflight, credential binding, the runner — can
// tell the difference.
type EndpointDeriver interface {
	Factory

	// DerivedEndpoint returns the endpoint a decoded configuration resolves to.
	//
	// It is called once, immediately after Decode, with that service's own
	// validated value. An error is a configuration error and refuses the target.
	DerivedEndpoint(config ServiceConfig) (host string, port uint16, err error)
}

// Registry maps a service kind to its factory.
//
// # It is the alternative to a switch, and that is the point
//
// ADR 0071 section 6.3: adding a fifth service must not require editing the
// runner, the config decoder, the aggregate report, the renderer or the
// exit-code mapping. A `switch kind { case "postgres": ... }` in this package
// would require editing one of those every time, which is the central
// conditional sprawl docs/ARCHITECTURE.md's extensibility rule forbids.
//
// # It is not a plugin system
//
// ADR 0009 declines that. Registration is explicit, happens once at a single
// composition point, and is passed in as arguments. There is no init(), no
// reflection, no discovery and no global mutable registry — a second Registry
// with different services is an ordinary value, which is what makes this
// testable without touching global state.
type Registry struct {
	factories map[string]Factory
	kinds     []string
}

// NewRegistry builds a registry from an explicit list.
//
// Duplicate registration is an error rather than a silent overwrite. A build
// that registered two decoders for one kind has a defect that would otherwise
// surface as "the wrong service validated this target", and the last-wins
// alternative makes the outcome depend on argument order.
func NewRegistry(factories ...Factory) (*Registry, error) {
	r := &Registry{factories: make(map[string]Factory, len(factories))}
	for _, factory := range factories {
		if factory == nil {
			return nil, fmt.Errorf("%w: a nil service factory was registered", ErrConfig)
		}
		kind := factory.Kind()
		if kind == "" {
			return nil, fmt.Errorf("%w: a service factory registered an empty kind", ErrConfig)
		}
		if _, exists := r.factories[kind]; exists {
			return nil, fmt.Errorf("%w: service kind %q is registered twice", ErrConfig, kind)
		}
		if factory.DefaultPort() == 0 {
			return nil, fmt.Errorf(
				"%w: service kind %q registered a zero default port", ErrConfig, kind)
		}
		r.factories[kind] = factory
		r.kinds = append(r.kinds, kind)
	}
	// Sorted once, at construction. Kinds() is used to build error messages, and
	// an error message that lists services in a different order on every run is
	// one nobody can diff.
	slices.Sort(r.kinds)
	return r, nil
}

// Kinds returns every registered service kind, in a stable order.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.kinds)
}

// lookup returns the factory for kind.
func (r *Registry) lookup(kind string) (Factory, bool) {
	if r == nil {
		return nil, false
	}
	factory, ok := r.factories[kind]
	return factory, ok
}

// unsupportedService builds the refusal for an unregistered kind.
//
// It lists what *is* available, because the two ways to reach this are a typo
// and a service svcdoctor does not have — and the list distinguishes them
// immediately.
func (r *Registry) unsupportedService(kind string) *Error {
	if kind == "" {
		return newError(CategoryUnsupportedService, fmt.Sprintf(
			"no service type is declared; write one of: %s", strings.Join(r.Kinds(), ", ")))
	}
	return newError(CategoryUnsupportedService, fmt.Sprintf(
		"service type %q is not supported; this build supports: %s",
		kind, strings.Join(r.Kinds(), ", ")))
}
