package config

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// LoadFile reads and validates a configuration file.
//
// It performs no network I/O, resolves no name, opens no socket, reads no
// environment variable and reads no credential file. The only file it touches is
// the one named here.
//
// ADR 0074 section 9: any configuration error means **zero targets are dialled**.
// This function is what makes that possible — it returns a whole validated
// configuration or an error, never a partial one, so a caller cannot start
// target 1 and discover target 18 is malformed afterwards.
func LoadFile(path string, registry *Registry) (Config, error) {
	source := cleanPath(path)
	data, err := readSource(path)
	if err != nil {
		return Config{}, err
	}
	config, err := Load(data, source, registry)
	if err != nil {
		return Config{}, attachSource(err, source)
	}
	return config, nil
}

// Load validates configuration bytes that a caller already holds.
//
// source names where the bytes came from and appears in messages. It is the
// seam that lets every test in this package run without touching a filesystem.
//
// # The order of the passes is the contract, not an implementation detail
//
//	1  syntax, and exactly one document
//	2  structure: anchors, aliases, merge keys, tags
//	3  version
//	4  strict decode: unknown fields, duplicate keys, types
//	5  targets, identities, services, credential references
//	6  the run block, which needs the targets
//
// Version comes before the strict decode because ADR 0071 section 4.3 requires
// that `version: 2` says so, rather than producing an avalanche of unknown-field
// errors about fields a future version legitimately defines. Structure comes
// before both because an alias expands into values that a decoder cannot tell
// from ones the operator wrote.
func Load(data []byte, source string, registry *Registry) (Config, error) {
	if registry == nil {
		return Config{}, fmt.Errorf("%w: no service registry was supplied", ErrConfig)
	}

	node, err := parseDocument(data)
	if err != nil {
		return Config{}, attachSource(err, source)
	}
	if err := checkStructure(node); err != nil {
		return Config{}, attachSource(err, source)
	}
	if err := checkVersion(data); err != nil {
		return Config{}, attachSource(err, source)
	}

	var doc document
	if err := strictDecode(data, &doc); err != nil {
		return Config{}, attachSource(err, source)
	}

	targets, err := validateTargets(doc.Targets, registry)
	if err != nil {
		return Config{}, attachSource(err, source)
	}

	run, err := doc.Run.validate(targets)
	if err != nil {
		return Config{}, attachSource(err, source)
	}

	return Config{Version: doc.Version, Run: run, Targets: targets}, nil
}

// validateTargets validates every target and enforces identity uniqueness.
//
// Targets keep their declared order throughout. Nothing here sorts, and the
// duplicate check uses a map for lookup only — the output order comes from the
// input slice, never from iterating that map (ADR 0073 §6.2).
func validateTargets(blocks []targetBlock, registry *Registry) ([]Target, error) {
	if len(blocks) == 0 {
		return nil, newError(CategoryInvalidField,
			"no targets are declared; a configuration must declare at least one").at("targets")
	}
	if len(blocks) > MaxTargets {
		return nil, newError(CategoryInvalidField, fmt.Sprintf(
			"declares %d targets, above the maximum of %d", len(blocks), MaxTargets)).
			at("targets")
	}

	seen := make(map[TargetID]int, len(blocks))
	targets := make([]Target, 0, len(blocks))

	for i, block := range blocks {
		path := fmt.Sprintf("targets[%d]", i)

		if block.ID == "" {
			// NewTargetID's message explains why an identifier is written rather
			// than derived; reaching it with the empty string produces exactly
			// that message.
			_, err := NewTargetID("")
			return nil, withPath(err, path)
		}
		if first, duplicate := seen[block.ID]; duplicate {
			return nil, newError(CategoryDuplicateID, fmt.Sprintf(
				"target identifier %q is already used by targets[%d]; identifiers must be "+
					"unique, and a repeat is refused rather than resolved by position",
				block.ID, first)).at(path).inTarget(block.ID.String())
		}
		seen[block.ID] = i

		target, err := validateTarget(block, registry)
		if err != nil {
			return nil, withTarget(withPath(err, path), block.ID.String())
		}
		targets = append(targets, target)
	}

	return targets, nil
}

// validateTarget validates one target and decodes its service configuration.
func validateTarget(block targetBlock, registry *Registry) (Target, error) {
	factory, ok := registry.lookup(block.Type)
	if !ok {
		return Target{}, registry.unsupportedService(block.Type)
	}

	if err := checkHostSyntax(block.Host); err != nil {
		return Target{}, err
	}

	port, err := resolvePort(block.Port, factory.DefaultPort())
	if err != nil {
		return Target{}, err
	}

	if err := block.TLS.validate(); err != nil {
		return Target{}, err
	}
	if err := block.Credentials.validate(); err != nil {
		return Target{}, err
	}

	timeout, err := resolveDuration(block.Timeout, DefaultTargetTimeout, "timeout")
	if err != nil {
		return Target{}, err
	}
	stepTimeout, err := resolveDuration(block.StepTimeout, DefaultStepTimeout, "step_timeout")
	if err != nil {
		return Target{}, err
	}
	if stepTimeout > timeout {
		return Target{}, newError(CategoryInvalidField, fmt.Sprintf(
			"step_timeout %s is above timeout %s, so no step could ever complete within the "+
				"target's own budget", stepTimeout, timeout)).at("step_timeout")
	}

	common := Common{
		ID:          block.ID,
		Host:        block.Host,
		Port:        port,
		Timeout:     timeout,
		StepTimeout: stepTimeout,
		TLS:         block.TLS,
		Credentials: block.Credentials,
	}

	// The service decodes its own subtree and validates it together with the
	// generic fields it is allowed to narrow. This is the only place the generic
	// core hands anything to a service, and it hands over an opaque node rather
	// than a decoded map.
	serviceConfig, err := factory.Decode(&block.Config, common)
	if err != nil {
		return Target{}, withLine(err, block.Config.Line())
	}
	if serviceConfig == nil {
		return Target{}, fmt.Errorf(
			"%w: service %q returned no configuration and no error", ErrConfig, block.Type)
	}

	return Target{
		ID:          block.ID,
		Service:     block.Type,
		Host:        block.Host,
		Port:        port,
		Timeout:     timeout,
		StepTimeout: stepTimeout,
		TLS:         block.TLS,
		Credentials: block.Credentials,
		Config:      serviceConfig,
	}, nil
}

// checkHostSyntax validates the host as text, and deliberately no further.
//
// # Why this is not probe.ParseHost
//
// ADR 0071 section 5 confines this package's imports to the YAML module, so the
// canonicalization rule cannot live here — and it should not, because there is
// already exactly one implementation of it. internal/app normalizes the host at
// the start of every DiagnoseX, through internal/probe, for the leaf commands
// and for anything else that calls it. A second normalization here is precisely
// the drift ADR 0042 records: before the rule was centralized, one spelling of an
// IPv6 address appeared in the anchor and another in the connection subject,
// inside a single report.
//
// So this checks what is a property of the *text* — that a host was written, and
// that it holds no whitespace or control character, which is true of no host on
// any transport. Everything else is a host semantics question with an owner.
//
// # This is not stricter than a leaf command, on purpose
//
// probe.ParseHost returns any non-empty non-literal string verbatim, so
// `--host db.example.com:5432` is accepted today and fails at resolution. Fleet
// mode inherits that rather than improving on it: a host accepted by
// `diagnose postgres` and refused here would be an inconsistency an operator
// hits while migrating a working invocation into a file.
func checkHostSyntax(host string) error {
	if host == "" {
		return newError(CategoryInvalidField, "a host is required").at("host")
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; c <= ' ' || c == 0x7f {
			return newError(CategoryInvalidField,
				"the host contains a space or a control character").at("host")
		}
	}
	return nil
}

// resolvePort applies the service default and refuses an out-of-range value.
func resolvePort(written *int, defaultPort uint16) (uint16, error) {
	if written == nil {
		return defaultPort, nil
	}
	value := *written
	if value < 1 || value > math.MaxUint16 {
		return 0, newError(CategoryInvalidField, fmt.Sprintf(
			"port %d is outside 1-65535", value)).at("port")
	}
	return uint16(value), nil
}

// resolveDuration applies a default and refuses a non-positive value.
func resolveDuration(written Duration, fallback time.Duration, field string) (time.Duration, error) {
	if written == 0 {
		return fallback, nil
	}
	value := written.Duration()
	if value <= 0 {
		return 0, newError(CategoryInvalidField, fmt.Sprintf(
			"%s %s must be positive", field, value)).at(field)
	}
	return value, nil
}

// attachSource records where a configuration came from, without overwriting a
// source a deeper error already set.
func attachSource(err error, source string) error {
	var configErr *Error
	if errors.As(err, &configErr) && configErr.source == "" {
		return configErr.from(source)
	}
	return err
}

// withPath prefixes the field path, so a defect deep inside a target reads as
// "targets[3].credentials.password" rather than as "password".
//
// The prefix is applied on the way out, by the loop that knows the index, rather
// than being threaded down into every validator. A validator names the field it
// is about and nothing more, which is what lets the same TLS validator serve
// four services without knowing where it was called from.
func withPath(err error, prefix string) error {
	var configErr *Error
	if !errors.As(err, &configErr) {
		return err
	}
	switch configErr.path {
	case "":
		return configErr.at(prefix)
	default:
		return configErr.at(prefix + "." + configErr.path)
	}
}

// withTarget records the target identifier when one is not already set.
func withTarget(err error, id string) error {
	var configErr *Error
	if errors.As(err, &configErr) && configErr.targetID == "" {
		return configErr.inTarget(id)
	}
	return err
}
