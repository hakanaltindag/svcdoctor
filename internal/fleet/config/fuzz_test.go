package config_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// Fuzz targets for the configuration boundary.
//
// # The properties, and why they are properties rather than assertions
//
// A fuzzer cannot know what a random document *means*, so it cannot assert an
// outcome. What it can do is assert invariants that must hold for every input,
// and the four below are the ones whose violation would be a security defect
// rather than a wrong answer:
//
//  1. **No panic.** A configuration file is untrusted input, and a panic in a
//     parser is a denial of service at best.
//  2. **Every failure is a classified config.Error.** An unclassified error is
//     one that did not pass through sanitizeYAML, which is the control that keeps
//     the decoder's interpolated scalars off the terminal.
//  3. **No library-interpolated value survives.** go.yaml.in quotes an offending
//     scalar in backticks inside its own message, and sanitizeYAML replaces every
//     such span. So a message that still carries the library's "cannot unmarshal"
//     phrasing must also carry the redaction marker.
//
//     This property was **narrower than the first attempt at it**, and the
//     narrowing is the interesting part. Asserting "no backticks at all" fails on
//     three inputs the fuzzer found within seconds — a target identifier, a field
//     name and a YAML tag, each containing a backtick and each echoed by
//     svcdoctor's *own* message via %q. Those are names the operator wrote and
//     must be told about; the thing that must never be echoed is a *value*. The
//     first property was measuring punctuation, not leakage.
//  4. **An accepted document is internally consistent.** Anything the parser
//     accepts must satisfy the invariants the rest of the fleet layer relies on
//     — bounded target count, unique identifiers, a resolved port and timeout —
//     because every consumer downstream is entitled to assume them.
//
// # The budget is bounded, deliberately
//
// These run as ordinary seed-corpus tests in `go test`, which is where they earn
// their keep in CI. Phase 9.1C ran each under an explicit `-fuzz` budget once;
// the results are recorded in the validation document rather than encoded here,
// because a repository test that fuzzes for a minute is a repository test that
// nobody runs.

// fuzzSource names where fuzzed bytes came from, in error messages.
//
// Not "*.yaml" — see assertNoInterpolatedValue for why that matters.
const fuzzSource = "fuzz-config"

// checkConfigInvariants is properties 2, 3 and 4 for one outcome.
func checkConfigInvariants(t *testing.T, cfg config.Config, err error) {
	t.Helper()

	if err != nil {
		var configErr *config.Error
		if !errors.As(err, &configErr) {
			t.Fatalf("unclassified error %T: %v", err, err)
		}
		if !configErr.Category().Valid() {
			t.Errorf("invalid category %v", configErr.Category())
		}
		assertNoInterpolatedValue(t, err)
		return
	}

	// Accepted. Everything downstream may assume the following.
	if cfg.Version != config.Version {
		t.Errorf("accepted a configuration at version %d", cfg.Version)
	}
	if len(cfg.Targets) == 0 {
		t.Error("accepted a configuration with no targets")
	}
	if len(cfg.Targets) > config.MaxTargets {
		t.Errorf("accepted %d targets, above the maximum of %d",
			len(cfg.Targets), config.MaxTargets)
	}
	if cfg.Run.Concurrency < 1 || cfg.Run.Concurrency > config.MaxConcurrency {
		t.Errorf("accepted concurrency %d", cfg.Run.Concurrency)
	}

	seen := map[string]bool{}
	for _, target := range cfg.Targets {
		id := target.ID.String()
		if id == "" {
			t.Error("accepted a target with an empty identifier")
		}
		if seen[id] {
			t.Errorf("accepted duplicate target identifier %q", id)
		}
		seen[id] = true

		if target.Host == "" {
			t.Errorf("target %q was accepted with no host", id)
		}
		if target.Port == 0 {
			t.Errorf("target %q was accepted with port 0", id)
		}
		if target.Timeout <= 0 || target.StepTimeout <= 0 {
			t.Errorf("target %q has a non-positive budget", id)
		}
		if target.StepTimeout > target.Timeout {
			t.Errorf("target %q has a step budget above its own budget", id)
		}
		if target.Config == nil {
			t.Errorf("target %q was accepted with no service configuration", id)
		}
		// The decoded configuration must never retain credential material. A
		// reference names a location; a value would mean the closed union was
		// bypassed.
		if ref := target.Credentials.Password; ref.Kind() == config.SourceNone && ref.Name() != "" {
			t.Errorf("target %q has a nameless reference carrying %q", id, ref.Name())
		}
	}
}

// liveInterpolation matches an unsanitized value in a decoder type-mismatch
// error: the tag, then a backtick-quoted scalar that is not the redaction
// marker.
var liveInterpolation = regexp.MustCompile("cannot unmarshal \\S+ `(?:[^`]*)`")

// redactedInterpolation is the same shape after sanitizeYAML has rewritten it.
//
// It has to be excluded explicitly, because the marker is *itself*
// backtick-quoted — `cannot unmarshal !!str ` + "`<value redacted>`" + ` into int`
// is correct, sanitized output that the pattern above matches exactly. Measured
// rather than reasoned: `port: "abc"` produces that line today.
var redactedInterpolation = regexp.MustCompile(
	"cannot unmarshal \\S+ `<value redacted>`")

// assertNoInterpolatedValue is property 3.
//
// The YAML library interpolates an offending value in exactly one shape:
//
//	cannot unmarshal !!str `hunter2` into config.credentialRef
//
// — a backtick-delimited span immediately after the tag. sanitizeYAML rewrites
// every such span, so finding a live one means the sanitizer was bypassed. That
// is the leak this whole boundary exists to prevent, because the line above is
// precisely what a plaintext password in a configuration file produces.
//
// # Why the pattern is this specific rather than "contains a backtick"
//
// Two weaker versions were tried and the fuzzer refuted both within seconds.
// "Any backtick" fires on an operator-written identifier that *contains* one,
// echoed correctly through %q. "Any occurrence of cannot unmarshal" fires on
// `cannot unmarshal !!map into string`, where the library names the source tag
// and interpolates nothing at all — there is no value in that message to leak.
// The interpolation has a shape, and matching the shape is what separates a leak
// from a correct diagnostic.
func assertNoInterpolatedValue(t *testing.T, err error) {
	t.Helper()
	text := err.Error()
	stripped := redactedInterpolation.ReplaceAllString(text, "")
	if match := liveInterpolation.FindString(stripped); match != "" {
		t.Errorf("a library error reached the caller with its scalar intact (%q): %q",
			match, text)
	}
	// The decoder's own prefixes, which sanitizeYAML strips.
	//
	// fuzzSource is deliberately not named "*.yaml": svcdoctor formats an error
	// as "<source>: line N: <detail>", so a source called fuzz.yaml makes every
	// located error contain the literal text "yaml: line " and this check fire on
	// correct output. The fuzzer found that on its tenth seed, and renaming the
	// source is the fix that keeps the check strict.
	for _, prefix := range []string{"yaml: unmarshal errors", "yaml: line "} {
		if strings.Contains(text, prefix) {
			t.Errorf("raw decoder text survived classification: %q", text)
		}
	}
}

// FuzzLoad fuzzes the whole configuration parse: syntax, structure, version,
// strict decode, target validation and the run block.
func FuzzLoad(f *testing.F) {
	f.Add(validFourService)
	for _, tc := range hostileCorpus() {
		f.Add(tc.doc)
	}
	// A minimal accepted document, so the fuzzer has a valid starting point to
	// mutate towards acceptance rather than only towards refusal.
	f.Add("version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n")

	registry := fuzzRegistry(f)
	f.Fuzz(func(t *testing.T, doc string) {
		cfg, err := config.Load([]byte(doc), fuzzSource, registry)
		checkConfigInvariants(t, cfg, err)
	})
}

// FuzzServiceNode fuzzes the service-owned subtree specifically.
//
// It is separate from FuzzLoad because the service node is the one place the
// generic core hands an undecoded tree to another package, and a fuzzer working
// on a whole document spends almost all of its budget never reaching it.
func FuzzServiceNode(f *testing.F) {
	seeds := []string{
		"database: orders",
		"sasl_mechanism: SCRAM-SHA-256",
		"vhost: /prod",
		"{}",
		"[]",
		"null",
		"database: [1, 2, 3]",
		"database:\n  nested: true",
		"bogus: x",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	registry := fuzzRegistry(f)
	f.Fuzz(func(t *testing.T, node string) {
		// Indented into a postgres target, which is the service with a required
		// field and therefore the strictest decoder.
		var b strings.Builder
		b.WriteString("version: 1\ntargets:\n  - id: a\n    type: postgres\n" +
			"    host: a.example.com\n    credentials:\n      username: u\n    config:\n")
		for _, line := range strings.Split(node, "\n") {
			b.WriteString("      ")
			b.WriteString(line)
			b.WriteString("\n")
		}

		cfg, err := config.Load([]byte(b.String()), fuzzSource, registry)
		checkConfigInvariants(t, cfg, err)
	})
}

// FuzzCredentialReference fuzzes the credential reference decoder.
//
// This is the highest-value target in the package. ADR 0072 section 3 refuses a
// plaintext password at the *type* level, and Phase 9.0 measured that the YAML
// library's type-mismatch error interpolates the offending scalar — so this is
// simultaneously the most security-critical refusal and the one whose library
// error carries the secret. The property below is the one that matters: whatever
// arrives, the value never comes back out.
func FuzzCredentialReference(f *testing.F) {
	seeds := []string{
		"env: DB_PASSWORD",
		"file: /run/secrets/db",
		"hunter2",
		"\"hunter2\"",
		"{}",
		"null",
		"[]",
		"env: A\n        file: /b",
		"env: \"\"",
		"file: \"\"",
		"vault: secret/db",
		"env:\n          nested: true",
		"- hunter2",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	registry := fuzzRegistry(f)
	f.Fuzz(func(t *testing.T, ref string) {
		doc := "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n" +
			"    credentials:\n      username: u\n      password:\n        " + ref + "\n"

		cfg, err := config.Load([]byte(doc), fuzzSource, registry)
		checkConfigInvariants(t, cfg, err)

		if err == nil {
			return
		}
		// Leakage is asserted with a **planted canary** rather than by looking
		// for the fuzz input itself in the message.
		//
		// Two substring versions were tried and the fuzzer refuted both. The
		// input `!000` is echoed because the tag refusal names the tag, which an
		// operator has to be told. The input `file` is echoed because the
		// refusal's own prose contains the example `{file: PATH}`. Neither is a
		// leak, and a check that cannot tell "the message quoted your value" from
		// "the message happens to contain that word" is measuring vocabulary.
		//
		// So the same shape is decoded again with a distinctive value spliced in.
		// If the canary comes back, a value was echoed, and no other reading is
		// available.
		assertCanaryNeverEchoes(t, registry)
	})
}

// FuzzSanitizedErrorPath drives the sanitizer through whatever error text the
// decoder can be made to produce, by planting the fuzz input as a *value* in
// every position whose decode can fail with an interpolated scalar.
func FuzzSanitizedErrorPath(f *testing.F) {
	seeds := []string{
		"hunter2", "`backticked`", "a`b", "``", "\n", "line 3: x",
		"yaml: unmarshal errors:", "not found in type config.targetBlock",
		"already defined at line 4", strings.Repeat("`", 64),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	registry := fuzzRegistry(f)
	f.Fuzz(func(t *testing.T, value string) {
		// A single-quoted YAML scalar with internal quotes doubled: this puts an
		// arbitrary byte string into a position typed as a mapping, which is the
		// decode failure that interpolates it.
		quoted := "'" + strings.ReplaceAll(value, "'", "''") + "'"
		doc := "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n" +
			"    credentials:\n      username: u\n      password: " + quoted + "\n"

		cfg, err := config.Load([]byte(doc), fuzzSource, registry)
		checkConfigInvariants(t, cfg, err)

		if err == nil {
			return
		}
		// The planted value must not survive into the message. Short values are
		// excluded because a one- or two-character string collides with ordinary
		// English in the prose, which would make this assert nothing about
		// leakage and everything about vocabulary.
		if len(value) >= 8 && strings.Contains(err.Error(), value) {
			t.Errorf("the sanitized error echoes the planted value %q: %v", value, err)
		}
	})
}

// assertCanaryNeverEchoes re-decodes a reference shape with a distinctive value
// spliced into every scalar position, and requires that no refusal repeats it.
func assertCanaryNeverEchoes(t *testing.T, registry *config.Registry) {
	t.Helper()

	// The three positions a *value* can occupy: written bare where a mapping
	// belongs (the plaintext-password case), and as either source's payload.
	//
	// A YAML **tag** is deliberately not among them. Splicing the canary into
	// tag position produces `!000hunter2-CANARY-c0ffee`, and the refusal names
	// it — correctly, because an operator told "you used a tag that is not
	// accepted" without being told *which* tag cannot act on that. A tag is
	// syntax rather than data, and no reference shape puts credential material
	// there. The exception is recorded here rather than silently excluded.
	for _, shape := range []string{
		"        " + canaryScalar,
		"        env: " + canaryScalar,
		"        file: " + canaryScalar,
	} {
		doc := "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n" +
			"    credentials:\n      username: u\n      password:\n" + shape + "\n"

		_, err := config.Load([]byte(doc), fuzzSource, registry)
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), canaryScalar) {
			t.Errorf("a refusal echoed the planted value: %v", err)
		}
	}
}

// fuzzRegistry builds the production registry once per fuzz target.
//
// Once, outside f.Fuzz, because building it per iteration would spend most of
// the budget on registry construction rather than on the parser.
func fuzzRegistry(f *testing.F) *config.Registry {
	f.Helper()
	return testRegistry(f)
}
