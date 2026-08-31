// Package rabbitmq owns the RabbitMQ shape of a multi-target configuration.
//
// It decodes and validates. It executes nothing, opens no socket, resolves no
// name and reads no credential.
//
// It is the service that proves ADR 0071 section 7.1's second clause: a generic
// field whose valid *range* is service-owned. See checkStepTimeout.
package rabbitmq

import (
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// Kind is the value of a target's `type` field.
const Kind = "rabbitmq"

// DefaultPort is `diagnose rabbitmq`'s default port.
const DefaultPort = 5672

// DefaultVHost is RabbitMQ's own `default_vhost`, and svcdoctor's default.
//
// Taken from internal/app rather than written again, so that one constant
// answers for the flag and for the file.
const DefaultVHost = app.DefaultVHost

// minStepTimeout is the floor below which a refusal reads as a local timeout.
//
// internal/cli/rabbitmq.go's bound, inherited unchanged: several RabbitMQ
// refusal paths hold the socket open for exactly three seconds on purpose, so a
// shorter budget reports the broker's deliberate delay as svcdoctor's own
// deadline expiring — an UNKNOWN where a FAIL was measurable (ADR 0070 §8).
const minStepTimeout = 3 * time.Second

// Config is a RabbitMQ target's own configuration.
type Config struct {
	// VHost is the virtual host to open. Empty means DefaultVHost.
	//
	// It is service-owned and it is **not** a credential authority component.
	// Connection.Start-Ok carries the credential and Connection.Open names the
	// vhost, in that order, so a vhost-scoped authority would have to gate a
	// transmission that already happened (ADR 0068 §6).
	VHost string `yaml:"vhost"`
}

// Kind reports the service this configuration belongs to.
func (c Config) Kind() string { return Kind }

// VHostOrDefault resolves the virtual host.
//
// Defaulted rather than required: the virtual host is rendered either way, so a
// defaulted `/` is a stated assumption rather than an unstated one, and a
// refusal naming a virtual host the operator never chose is self-explaining
// (ADR 0067 §3.1).
func (c Config) VHostOrDefault() string {
	if c.VHost == "" {
		return DefaultVHost
	}
	return c.VHost
}

// Factory registers RabbitMQ with the generic configuration core.
type Factory struct{}

// Kind returns the registration key.
func (Factory) Kind() string { return Kind }

// DefaultPort returns the port used when a target names none.
func (Factory) DefaultPort() uint16 { return DefaultPort }

// Decode turns the `config:` subtree into a Config and validates the target.
func (Factory) Decode(node *config.ServiceNode, common config.Common) (config.ServiceConfig, error) {
	var cfg Config
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}

	if err := checkVHost(cfg.VHostOrDefault()); err != nil {
		return nil, err
	}
	if err := checkStepTimeout(common.StepTimeout); err != nil {
		return nil, err
	}

	return cfg, nil
}

// checkVHost enforces the protocol's own `path` domain limit.
//
// Refused rather than truncated, and refused before anything is opened:
// truncating would name a *different* virtual host than the one the report says
// was requested.
func checkVHost(vhost string) error {
	if len(vhost) > app.MaxVHostBytes {
		return config.InvalidField("config.vhost", fmt.Sprintf(
			"virtual host is %d bytes, above the %d byte protocol maximum",
			len(vhost), app.MaxVHostBytes))
	}
	return nil
}

// checkStepTimeout narrows a generic field's range for one service.
//
// # This is the measured instance of ADR 0071 section 7.1's second clause
//
// `step_timeout` means the same thing for all four services — a bound on each
// probe call and each protocol exchange — so the field is generic. Its valid
// range is not: RabbitMQ has a floor and the other three do not.
//
// Making the whole field service-owned would repeat it four times. Making the
// range generic would either impose this floor on services that do not need it,
// or drop it for the one that does. Generic field, service-owned validation is
// the only split that is true, and this function is what that looks like.
func checkStepTimeout(stepTimeout time.Duration) error {
	if stepTimeout <= minStepTimeout {
		return config.InvalidField("step_timeout", fmt.Sprintf(
			"step_timeout %s must exceed %s for a RabbitMQ target: the broker delays several "+
				"refusals by exactly that long, and a shorter budget reports the delay as a "+
				"local timeout instead of the refusal it is", stepTimeout, minStepTimeout))
	}
	return nil
}
