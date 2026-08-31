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
}

// Factory is what a service registers so the generic core can handle its targets.
//
// Four small methods, and none of them performs I/O, opens a connection, reads
// an environment variable or resolves a credential. A factory turns bytes into a
// validated value and does nothing else in this phase.
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
