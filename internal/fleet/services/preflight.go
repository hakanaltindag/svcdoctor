package services

import (
	"errors"
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/security/trustsource"
)

// ErrPreflight marks a defect a target's own configuration carries, found
// before the run starts and without touching the network.
//
// It is a **configuration** error and it exits 2, alongside a malformed
// document and an unresolvable credential reference. internal/cli/exit.go maps
// it, and internal/cli/run_test.go pins the code.
var ErrPreflight = errors.New("preflight")

// PreflightError is one target's pre-execution configuration defect.
//
// A type rather than a wrapped sentinel, for the reason secret.ResolutionError
// is one: the sentinel is how a caller *classifies* the failure and the string
// is what an operator *reads*, and printing "preflight: " in front of every
// message would put a word from the first job into the second one.
type PreflightError struct {
	// TargetID is the identifier the configuration declared. It is operator
	// text and it is already in the file the operator is looking at, so naming
	// it costs nothing and finding the target without it costs a search.
	TargetID string

	// Field is the configuration path, in the file's own vocabulary.
	Field string

	cause error
}

// Error names the target, the field and the reason. For stderr.
func (e *PreflightError) Error() string {
	return fmt.Sprintf("target %q: %s: %v", e.TargetID, e.Field, e.cause)
}

// Unwrap exposes the underlying validator's error, so a caller may still test
// for probe.ErrUnsupportedHost or a trustsource sentinel.
func (e *PreflightError) Unwrap() error { return e.cause }

// Is reports that every PreflightError matches ErrPreflight.
func (e *PreflightError) Is(target error) bool { return target == ErrPreflight }

// PreflightAll validates every target's local transport inputs before any
// target runs.
//
// # Why this exists
//
// internal/domain/executionstate.go states an invariant in its own words:
// "configuration errors never reach execution at all — ADR 0074 §9 requires a
// whole configuration to validate before any target is dialled, so the only
// failures reachable here are svcdoctor-local ones during a run."
//
// Phase 9.2A measured two configuration errors that reached execution anyway,
// and both are the same shape: a value the operator wrote, which the *leaf*
// commands validate at invocation and refuse with exit 2, and which the fleet
// path carried all the way into a runner. There it became
// EXECUTION_FAILED / INTERNAL — "one of svcdoctor's own invariants failed" — at
// exit 4.
//
//	host: fe80::1%en0        leaf: exit 2   fleet: exit 4, class INTERNAL
//	tls.ca_file: /nope.pem   leaf: exit 2   fleet: exit 4, class INTERNAL
//
// Three things were wrong with that and only one of them is cosmetic. An
// operator was told to file a bug against svcdoctor for a typo. A CI policy that
// retries on 4 — the code that means "incomplete, the measurement did not
// finish" — retries forever on a value that will never work. And the message
// carried a filesystem path into a report the operator may then share, which is
// the leak recorded as UX-B01.
//
// # Why it lives here and not in internal/fleet/config
//
// The configuration package cannot reach either validator. It may not import
// internal/probe or internal/security/* — both are enforced by
// test/security/fleet_boundary_test.go, and the second is what makes "the parser
// cannot construct a secret" a property of the build rather than a rule.
//
// This package is already the bridge that holds probe types on the fleet layer's
// behalf, for exactly this reason. So preflight lives one layer above the
// parser, beside the credential preflight that already runs at the same point
// and for the same purpose.
//
// # It duplicates no service logic
//
// There is no service switch here and no per-service rule. `host` and the `tls`
// block are fields of the **generic envelope** (ADR 0071 §7.3), so one
// service-neutral pass covers all four services and every service added later.
//
// Both checks call the same function the runner calls later — probe.ParseHost is
// the single host classification (ADR 0059) and trustsource.Load is the single
// trust-material loader. Preflight does not re-implement either rule; it runs
// them earlier, where the answer is still a statement about the configuration.
//
// # What it does not do
//
// No name is resolved, no socket is opened, no handshake is performed, no
// credential is read and no protocol is spoken. probe.ParseHost parses a string;
// trustsource.Load reads one operator-named file. That boundary is proved by
// test/security/fleet_preflight_test.go, which counts resolver and dialer calls
// and requires zero.
//
// Targets are visited in declared configuration order and the first defect
// returns, so the same file always reports the same error.
func PreflightAll(cfg config.Config) error {
	for _, target := range cfg.Targets {
		if err := PreflightTarget(target); err != nil {
			return err
		}
	}
	return nil
}

// PreflightTarget validates one target's local transport inputs.
//
// The error names the target and the field, matching the shape the credential
// preflight already produces, so an operator reading stderr sees one grammar for
// every pre-execution failure:
//
//	svcdoctor: target "orders-db": host: <reason>
//	svcdoctor: target "orders-db": tls.ca_file: <reason>
//	svcdoctor: target "orders-db": credential resolution failed: <reason>
func PreflightTarget(target config.Target) error {
	if _, err := probe.ParseHost(target.Host); err != nil {
		return &PreflightError{
			TargetID: string(target.ID),
			Field:    "host",
			cause:    errors.New(probe.Reason(err)),
		}
	}

	// A target that plans no encryption names no trust material, so a plaintext
	// target touches no disk here. TLS.Enabled() is the same predicate
	// TLSOptions uses, so the two agree by construction.
	if !target.TLS.Enabled() {
		return nil
	}

	// The trust source is read exactly as the runner will read it: the same
	// loader, the same bounds, the same refusal for an empty or
	// certificate-free file, and the same phrasing the four leaf commands use.
	//
	// The pool is discarded. Preflight proves the material loadable and retains
	// nothing, for the same reason the credential preflight retains no secret
	// (ADR 0072 §5.2): keeping it until execution would mean holding every
	// target's material for the whole run.
	if _, err := trustsource.Load(target.TLS.CAFile); err != nil {
		return &PreflightError{
			TargetID: string(target.ID),
			Field:    "tls.ca_file",
			cause:    errors.New(trustsource.Reason(err)),
		}
	}

	return nil
}
