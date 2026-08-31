package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// The Phase 9.1A single-target regression surface.
//
// # Why a whole file for something that changed nothing
//
// Phase 9.1A built a multi-target configuration foundation with an
// environment-backed credential source, next to four released commands whose
// credential sources are deliberately file and stdin only (ADR 0049 §5). The
// most plausible way that decision leaks is someone reasoning that the leaf
// commands should have the new source too, or that they should learn to read a
// configuration file.
//
// Neither happened, and these are the sentences that say so from inside the CLI
// package. They are cheap, and the thing they protect is the boundary that made
// the fleet layer's environment source acceptable in the first place.

// leafFlagSurface is exactly the flags each `diagnose` command exposes.
//
// Every entry was present before Phase 9.1A and is present after it. A flag
// added, removed or renamed fails here, which is what makes "the leaf commands
// are untouched" checkable rather than asserted.
var leafFlagSurface = map[string][]string{
	"postgres": {
		"host", "port", "user", "database",
		"timeout", "step-timeout",
		"tls", "tls-ca-file", "tls-server-name", "tls-insecure",
		"output", "password-file", "password-stdin", "shareable",
	},
	"kafka": {
		"host", "port", "sasl-mechanism", "user",
		"timeout", "step-timeout",
		"tls", "tls-ca-file", "tls-server-name", "tls-insecure",
		"output", "password-file", "password-stdin", "shareable",
	},
	"redis": {
		"host", "port", "username",
		"timeout", "step-timeout",
		"tls", "tls-ca-file", "tls-server-name", "tls-insecure",
		"output", "password-file", "password-stdin", "shareable",
	},
	"rabbitmq": {
		"host", "port", "vhost", "username",
		"timeout", "step-timeout",
		"tls", "tls-ca-file", "tls-server-name", "tls-insecure",
		"output", "password-file", "password-stdin", "shareable",
	},
}

// TestTheLeafCommandFlagSurfacesAreUnchanged pins all four.
//
// Each flag is probed by invoking the command with it and confirming the
// invocation is not refused as unknown. `flag` reports an unrecognized flag with
// "flag provided but not defined", which is the string a missing flag produces
// and no present flag can.
func TestTheLeafCommandFlagSurfacesAreUnchanged(t *testing.T) {
	for service, flags := range leafFlagSurface {
		for _, name := range flags {
			t.Run(service+"/"+name, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				app := newTestApp(&stdout, &stderr)
				// A deliberately empty value: the flag may still be rejected on
				// its value, which is fine. What must not happen is the parser
				// reporting that it does not know the flag at all.
				app.Run(context.Background(),
					[]string{"diagnose", service, "--" + name + "="})

				if strings.Contains(stderr.String(), "not defined") {
					t.Errorf("`diagnose %s` no longer defines --%s.\n\n"+
						"The four leaf command surfaces are frozen; Phase 9.1A added a "+
						"configuration layer beside them and changed none of them.",
						service, name)
				}
			})
		}
	}
}

// TestNoLeafCommandGainedAConfigurationFlag keeps the two worlds apart.
//
// A `--config` on a leaf command would mean one invocation could name both a
// single endpoint and a file describing many, and the precedence between them
// would be a decision nobody made. Multi-target execution gets its own command
// in Phase 9.1B (ADR 0074 §10.1).
func TestNoLeafCommandGainedAConfigurationFlag(t *testing.T) {
	forbidden := []string{
		"config", "config-file", "targets", "concurrency",
		"password-env", "target",
	}
	for service := range leafFlagSurface {
		for _, name := range forbidden {
			t.Run(service+"/"+name, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				app := newTestApp(&stdout, &stderr)
				code := app.Run(context.Background(),
					[]string{"diagnose", service, "--" + name + "=x"})

				if code != ExitUsage {
					t.Errorf("`diagnose %s --%s` exited %d, want %d; the leaf commands take "+
						"one endpoint from flags and never a configuration file",
						service, name, code, ExitUsage)
				}
				if !strings.Contains(stderr.String(), "not defined") {
					t.Errorf("`diagnose %s --%s` was not refused as an unknown flag: %s",
						service, name, stderr.String())
				}
			})
		}
	}
}

// TestTheRunCommandIsRouted was TestTheRunCommandIsNotRoutedYet in Phase 9.1A.
//
// # It was turned around rather than deleted
//
// The same treatment the RabbitMQ contract-freeze guard got at Phase 8.2: where
// it asserted that nothing existed, it now asserts that exactly the right thing
// does. A negative guard that is deleted the moment its subject arrives never
// records that the arrival was deliberate.
//
// ADR 0048's rule is why the command was absent rather than present-and-refusing
// in 9.1A: no command is ever exposed as a stub, and an operator reasonably reads
// a command's presence as a promise.
func TestTheRunCommandIsRouted(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)

	// No --config, so this is refused on its own terms rather than as an unknown
	// command. That distinction is the whole assertion.
	code := app.Run(context.Background(), []string{"run"})

	if code != ExitUsage {
		t.Errorf("`svcdoctor run` with no --config exited %d, want %d", code, ExitUsage)
	}
	if strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("`run` is still unrouted: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--config is required") {
		t.Errorf("stderr = %q, want the missing-config refusal", stderr.String())
	}
}

// TestTheRunCommandRefusesConfigStdin pins ADR 0074 section 10.3.
func TestTheRunCommandRefusesConfigStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)

	code := app.Run(context.Background(), []string{"run", "--config", "-"})

	if code != ExitUsage {
		t.Errorf("`--config -` exited %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "regular file") {
		t.Errorf("stderr = %q, want the reason stated", stderr.String())
	}
}

// TestTheRunCommandExposesOnlyRunGlobalFlags is ADR 0074 section 10.2.
//
// Every flag it has is run-global, and every flag it must not have is refused as
// unknown. The second list is the load-bearing one: a `--password-file` here
// would make one ambient secret available to N targets, which is exactly the
// cross-contamination ADR 0072 §7 exists to prevent.
func TestTheRunCommandExposesOnlyRunGlobalFlags(t *testing.T) {
	present := []string{"config", "timeout", "concurrency", "output", "shareable"}
	for _, name := range present {
		t.Run("present/"+name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			app := newTestApp(&stdout, &stderr)
			app.Run(context.Background(), []string{"run", "--" + name + "="})
			if strings.Contains(stderr.String(), "not defined") {
				t.Errorf("`run` does not define --%s", name)
			}
		})
	}

	absent := []string{
		"password-file", "password-stdin", "password-env",
		"host", "port", "vhost", "broker", "username", "user", "database",
		"sasl-mechanism", "target", "type", "filter",
		"tls", "tls-ca-file", "tls-server-name", "tls-insecure", "step-timeout",
	}
	for _, name := range absent {
		t.Run("absent/"+name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			app := newTestApp(&stdout, &stderr)
			code := app.Run(context.Background(), []string{"run", "--" + name + "=x"})

			if code != ExitUsage {
				t.Errorf("`run --%s` exited %d, want %d; target data belongs in the "+
					"configuration", name, code, ExitUsage)
			}
			if !strings.Contains(stderr.String(), "not defined") {
				t.Errorf("`run --%s` was not refused as unknown: %s", name, stderr.String())
			}
		})
	}
}

// TestTheRootUsageNamesOnlyImplementedCommands keeps the help honest.
//
// It was TestTheRootUsageNamesNoUnimplementedCommand in 9.1A. `run` moved from
// the forbidden list to the required one; `inspect`, `batch`, `multi` and
// `fleet` stayed forbidden, because none of them exists.
func TestTheRootUsageNamesOnlyImplementedCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)
	app.Run(context.Background(), []string{"--help"})

	// Listed commands only, never prose. The help legitimately contains the word
	// "run" in a sentence — *"from where you run it"* — and a substring search
	// matched it, which is the false positive this shape exists to avoid.
	var commands []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, "  ") || trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		commands = append(commands, strings.Fields(trimmed)[0])
	}

	for _, name := range commands {
		switch name {
		case "batch", "multi", "fleet", "inspect":
			t.Errorf("root help lists the command %q, which does not exist.\n\n"+
				"ADR 0048: no command is ever exposed as a stub, and help that names one is "+
				"the same promise as a command that parses and refuses.\n%s",
				name, stdout.String())
		}
	}

	for _, required := range []string{"diagnose", "run"} {
		var found bool
		for _, name := range commands {
			if name == required {
				found = true
			}
		}
		if !found {
			t.Errorf("root help does not list %q; parsed commands were %v", required, commands)
		}
	}
}

// newTestApp builds a command environment whose seams never reach a network.
//
// The four diagnose functions are left at their production values deliberately:
// every invocation in this file is refused during argument parsing, before a
// composition root could be called, and a test that stubbed them could not tell
// the difference between "refused early" and "ran and returned nothing".
func newTestApp(stdout, stderr *bytes.Buffer) *App {
	return New(strings.NewReader(""), stdout, stderr, "test")
}
