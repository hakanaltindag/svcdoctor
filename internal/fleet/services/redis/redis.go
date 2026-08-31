// Package redis owns the Redis shape of a multi-target configuration.
//
// It decodes and validates. It executes nothing, opens no socket, resolves no
// name and reads no credential.
//
// # Redis adds no field of its own, and that is the honest answer
//
// `diagnose redis` exposes `--host`, `--port`, `--username` and the shared
// timeout, TLS, credential and output flags — and nothing else. Every one of
// those is already generic (ADR 0071 §7.2), so Config is empty and a Redis
// target needs no `config:` block at all.
//
// It would have been easy to invent one. A `db:` field is the obvious candidate
// and it is deliberately absent: `SELECT` is not in the Redis BASIC command
// allowlist that ADR 0063 froze to three commands, so a `db:` field would be
// configuration for behaviour svcdoctor does not have. Accepting it and ignoring
// it is worse than not accepting it, because an inert field reads as an honoured
// one at the call site.
package redis

import (
	"context"
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Kind is the value of a target's `type` field.
const Kind = "redis"

// DefaultPort is `diagnose redis`'s default port.
const DefaultPort = 6379

// Config is a Redis target's own configuration.
//
// Empty, and it stays a named type rather than becoming nil so that every
// service is reached the same way and the generic core needs no special case for
// "this one has no configuration".
type Config struct{}

// Kind reports the service this configuration belongs to.
func (c Config) Kind() string { return Kind }

// Factory registers Redis with the generic configuration core and with the
// runner registry.
//
// One type implementing both interfaces, so a service is registered once. The
// zero Factory is usable for configuration alone — Decode reads no field.
type Factory struct {
	// Env carries the probe seams, the vantage and the version. Required for
	// Run; unused by Decode.
	Env services.Environment
}

// Kind returns the registration key.
func (Factory) Kind() string { return Kind }

// DefaultPort returns the port used when a target names none.
func (Factory) DefaultPort() uint16 { return DefaultPort }

// Decode validates a Redis target.
//
// # An empty username is passed through as empty
//
// `default` is never synthesized. The two AUTH forms have different observable
// behaviour against a `nopass` user, so supplying an identity the operator did
// not write would change what the run measures (ADR 0064 §5). Nothing here fills
// it in, and nothing requires it.
func (Factory) Decode(node *config.ServiceNode, _ config.Common) (config.ServiceConfig, error) {
	var cfg Config
	// Decoding an empty struct with unknown fields refused is what makes
	// `config: {db: 0}` an error rather than a silently ignored field.
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Run turns a validated target into app.RedisParams and calls the existing
// composition root.
//
// Redis negotiates no encryption in band, so the TLS plan is ordinary
// out-of-band transport TLS and the generic chain performs it — the same shape
// Kafka and RabbitMQ use, and the reason those three share this mapping while
// PostgreSQL does not.
func (f Factory) Run(
	ctx context.Context, target config.Target, credential security.Credential,
) (run.Outcome, error) {
	if _, ok := target.Config.(Config); !ok {
		return run.Outcome{}, fmt.Errorf(
			"redis runner received %T, which is not a Redis configuration", target.Config)
	}

	options, err := services.TLSOptions(target.TLS)
	if err != nil {
		return run.Outcome{}, err
	}

	result, err := app.DiagnoseRedis(ctx, app.RedisParams{
		Host:        target.Host,
		Port:        target.Port,
		Username:    target.Credentials.Username,
		Credential:  credential,
		Resolver:    f.Env.Resolver,
		Dialer:      f.Env.Dialer,
		TLS:         options,
		StepTimeout: target.StepTimeout,
		Vantage:     f.Env.Vantage,
		Version:     f.Env.Version,
	})
	if err != nil {
		return run.Outcome{}, err
	}
	return run.Outcome{Report: result.Report(), Incomplete: result.Incomplete()}, nil
}
