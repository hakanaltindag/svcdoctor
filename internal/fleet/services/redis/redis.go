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
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
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

// Factory registers Redis with the generic configuration core.
type Factory struct{}

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
