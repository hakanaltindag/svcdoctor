//go:build integration

package rabbitmq

import (
	"strings"
	"testing"
)

// builtinExchanges are the exchanges every RabbitMQ virtual host is born with.
//
// The empty name is the default exchange and is one of them. Anything outside
// this set had to be declared, and svcdoctor cannot declare one.
var builtinExchanges = []string{
	"", "amq.direct", "amq.fanout", "amq.headers", "amq.match",
	"amq.rabbitmq.trace", "amq.topic",
}

// TestTheBrokersHoldNoApplicationTopology is the runtime half of the
// zero-topology contract.
//
// The structural guards in test/security prove svcdoctor **cannot express** a
// channel, queue or exchange method. This proves the consequence on real
// brokers that have just served every scenario in this package: they hold no
// queue at all, and no exchange beyond the ones they shipped with.
//
// It creates nothing in order to prove absence. That is deliberate — a test that
// declared a queue to check it could be deleted would be the only thing in the
// repository that had ever declared one.
func TestTheBrokersHoldNoApplicationTopology(t *testing.T) {
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			for _, vhost := range []string{"/", vhostLimit} {
				queues := rabbitmqctl(t, v.container, "list_queues", "-p", vhost, "name")
				for _, line := range strings.Split(queues, "\n") {
					line = strings.TrimSpace(line)
					if line == "" || line == "name" {
						continue
					}
					t.Errorf("vhost %q holds queue %q; RabbitMQ BASIC declares none",
						vhost, line)
				}
			}

			// Every exchange present must be one the broker shipped with.
			//
			// A subset check rather than exact equality, deliberately: the
			// default exchange has an empty name and where it lands in the
			// output varies by version, so requiring it back would test
			// rabbitmqctl's formatting rather than svcdoctor's behaviour. The
			// contract is that nothing was **added**, and that is what this asks.
			raw := rabbitmqctl(t, v.container, "list_exchanges", "-p", "/", "name")
			for _, line := range strings.Split(raw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || line == "name" {
					continue
				}
				if !isBuiltinExchange(line) {
					t.Errorf("vhost %q holds exchange %q, which is not built in; "+
						"RabbitMQ BASIC declares none", "/", line)
				}
			}
		})
	}
}

func isBuiltinExchange(name string) bool {
	for _, builtin := range builtinExchanges {
		if name == builtin {
			return true
		}
	}
	return false
}

// TestNoConnectionOutlivesItsRun pins the other half of ADR 0067 §2: one
// connection, closed politely, with nothing left behind.
//
// A leaked connection would also be the only way a channel could still be open
// by the time this runs.
func TestNoConnectionOutlivesItsRun(t *testing.T) {
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			// A healthy run, so there is definitely something to leak.
			result := run(t, runOptions{port: v.tlsPort, username: userApp,
				password: passApp, tls: trustFixtureCA(t)})
			if !hasNodeAt(t, result, stepOpen) {
				t.Fatal("the scenario did not reach Connection.Open")
			}

			raw := rabbitmqctl(t, v.container, "list_connections", "name")
			for _, line := range strings.Split(raw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || line == "name" {
					continue
				}
				t.Errorf("a connection is still open after the run: %q", line)
			}

			channels := rabbitmqctl(t, v.container, "list_channels", "name")
			for _, line := range strings.Split(channels, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || line == "name" {
					continue
				}
				t.Errorf("a channel exists: %q; RabbitMQ BASIC never sends Channel.Open", line)
			}
		})
	}
}
