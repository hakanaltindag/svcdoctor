package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// The Phase 9.1C hostile configuration corpus.
//
// # What this adds over the Phase 9.1A matrix
//
// The 9.1A matrix asks *"is each frozen refusal implemented"*, one case per
// frozen decision. This asks the adversarial question instead: given a document
// written to break the parser rather than to configure a run, does anything
// escape the boundary? So it holds shapes no frozen decision names — an embedded
// NUL, a 200-deep nesting, a 900 KiB scalar, a comment that looks like a merge
// key, a quoted string that looks like an interpolation — and it asserts four
// properties over **every** one of them at once rather than a bespoke assertion
// per case.
//
// # The four properties, and why they are checked together
//
//  1. No panic. A configuration file is untrusted input.
//  2. Either a *classified* config.Error or a valid Config. Never a bare error,
//     because a bare error is one that escaped classification and therefore
//     escaped sanitization.
//  3. No secret-shaped scalar in the message. The decoder interpolates offending
//     values into its own errors, so this is the property that keeps a plaintext
//     password off the terminal.
//  4. No network. Guaranteed structurally — this package imports only the YAML
//     module — and restated per case in TestValidationPerformsNoNetworkIO.
//
// Checking them together is what makes the corpus cheap to extend: a new hostile
// shape is one table row, not a new test.

// canaryScalar is the value planted wherever a case can carry one.
//
// It is deliberately distinctive so that finding it in a message is unambiguous,
// and it is shaped like a password because the decoder's type-mismatch error is
// the one place a real one would surface.
const canaryScalar = "hunter2-CANARY-c0ffee"

// hostileCase is one adversarial document.
type hostileCase struct {
	name string
	doc  string

	// accepted records that this shape is *valid* YAML the schema legitimately
	// takes. It is not a weakness: a corpus that expected every hostile-looking
	// document to be refused would be asserting that the parser is paranoid
	// rather than correct, and quoted text containing "<<:" really is a string.
	accepted bool
}

// hostileCorpus is the Phase 9.1C section 4 list, in its order.
func hostileCorpus() []hostileCase {
	valid := func(body string) string {
		return "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n" + body
	}

	return []hostileCase{
		{name: "duplicate root key", doc: "version: 1\nversion: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n"},
		{name: "duplicate nested key", doc: "version: 1\ntargets:\n  - id: a\n    id: b\n    type: redis\n    host: a.example.com\n"},
		{name: "merge key", doc: "version: 1\ndefaults: &d\n  type: redis\ntargets:\n  - id: a\n    <<: *d\n    host: a.example.com\n"},
		{name: "alias", doc: "version: 1\nx: &anchor a.example.com\ntargets:\n  - id: a\n    type: redis\n    host: *anchor\n"},
		{name: "anchor alone", doc: "version: 1\ntargets:\n  - id: &name a\n    type: redis\n    host: a.example.com\n"},
		{name: "recursive alias", doc: "version: 1\ntargets: &t\n  - id: a\n    type: redis\n    host: a.example.com\n    config: *t\n"},
		{name: "custom tag", doc: "version: 1\ntargets:\n  - id: !mytag a\n    type: redis\n    host: a.example.com\n"},
		{name: "unknown core-looking tag", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: !!binary aGk=\n"},
		{name: "timestamp tag", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: !!timestamp 2026-01-01\n"},
		{name: "multi-document", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n---\nversion: 1\n"},
		{name: "trailing second document marker", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n---\n"},
		{name: "explicit null credential", doc: valid("    credentials:\n      username: u\n      password: null\n")},
		{name: "scalar credential", doc: valid("    credentials:\n      username: u\n      password: " + canaryScalar + "\n")},
		{name: "quoted scalar credential", doc: valid("    credentials:\n      username: u\n      password: \"" + canaryScalar + "\"\n")},
		{name: "sequence where mapping required", doc: valid("    credentials:\n      username: u\n      password:\n        - " + canaryScalar + "\n")},
		{name: "sequence where the target mapping is required", doc: "version: 1\ntargets:\n  - - id: a\n"},
		{name: "env and file together", doc: valid("    credentials:\n      username: u\n      password:\n        env: A\n        file: /b\n")},
		{name: "neither env nor file", doc: valid("    credentials:\n      username: u\n      password: {}\n")},
		{name: "unknown credential source", doc: valid("    credentials:\n      username: u\n      password:\n        vault: secret/a\n")},
		{name: "unknown service field", doc: valid("    config:\n      bogus: x\n")},
		{name: "unknown root field", doc: "version: 1\nbogus: x\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n"},
		{name: "unknown service type", doc: "version: 1\ntargets:\n  - id: a\n    type: cassandra\n    host: a.example.com\n"},
		{name: "unsupported version", doc: "version: 99\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n"},
		{name: "absent version", doc: "targets:\n  - id: a\n    type: redis\n    host: a.example.com\n"},
		{name: "empty target id", doc: "version: 1\ntargets:\n  - id: \"\"\n    type: redis\n    host: a.example.com\n"},
		{name: "oversized target id", doc: "version: 1\ntargets:\n  - id: " + strings.Repeat("a", 64) + "\n    type: redis\n    host: a.example.com\n"},
		{name: "uppercase target id", doc: "version: 1\ntargets:\n  - id: Orders\n    type: redis\n    host: a.example.com\n"},
		{name: "invalid characters in target id", doc: "version: 1\ntargets:\n  - id: \"a b/c\"\n    type: redis\n    host: a.example.com\n"},
		{name: "duplicate target ids", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n  - id: a\n    type: redis\n    host: b.example.com\n"},
		{name: "zero targets", doc: "version: 1\ntargets: []\n"},
		{name: "no targets key at all", doc: "version: 1\n"},
		{name: "malformed indentation with a tab", doc: "version: 1\ntargets:\n\t- id: a\n"},
		{name: "malformed UTF-8", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: \"a\xff\xfe.example.com\"\n"},
		{name: "embedded NUL", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: \"a\x00b.example.com\"\n"},
		{name: "comment that looks like a merge key", doc: "version: 1\n# <<: *evil\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n", accepted: true},
		{name: "quoted string containing a merge key", doc: valid("    credentials:\n      username: \"<<: *evil\"\n"), accepted: true},
		{name: "quoted string containing an interpolation", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: \"${DB_HOST}\"\n", accepted: true},
		{name: "quoted string containing an anchor sigil", doc: "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: \"&anchor.example.com\"\n", accepted: true},
	}
}

// TestTheHostileCorpusNeverEscapesTheConfigBoundary runs the whole corpus and
// asserts the four properties over each case.
func TestTheHostileCorpusNeverEscapesTheConfigBoundary(t *testing.T) {
	for _, tc := range hostileCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := load(t, tc.doc)

			if tc.accepted {
				if err != nil {
					t.Fatalf("this document is legitimate YAML the schema accepts, "+
						"and it was refused: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("accepted, and it must not be; it produced %d target(s)",
					len(cfg.Targets))
			}
			assertClassifiedAndSafe(t, err)
		})
	}
}

// assertClassifiedAndSafe is properties 2 and 3, applied to one error.
func assertClassifiedAndSafe(t *testing.T, err error) {
	t.Helper()

	var configErr *config.Error
	if !errors.As(err, &configErr) {
		t.Fatalf("returned %T, not a classified *config.Error; an unclassified error is "+
			"one that escaped sanitization: %v", err, err)
	}
	if !configErr.Category().Valid() {
		t.Errorf("category %v is not one of the closed set", configErr.Category())
	}

	text := err.Error()
	if strings.Contains(text, canaryScalar) {
		t.Errorf("the error echoes the planted scalar: %q", text)
	}
	// The decoder's own formatter quotes offending values in backticks. The
	// sanitizer removes every backtick-quoted span, so a surviving pair means a
	// path that bypassed it.
	if strings.Count(text, "`") > 0 && !strings.Contains(text, "<value redacted>") {
		t.Errorf("the error carries an unredacted backtick-quoted span: %q", text)
	}
}

// TestPathologicalNestingIsBoundedRatherThanFatal covers the two shapes whose
// hazard is resource use rather than acceptance, so they get their own
// assertions: what matters is that they terminate and stay classified.
func TestPathologicalNestingIsBoundedRatherThanFatal(t *testing.T) {
	t.Run("deep nesting", func(t *testing.T) {
		const depth = 200
		var b strings.Builder
		b.WriteString("version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n    config:\n")
		for i := range depth {
			b.WriteString(strings.Repeat("  ", i+4))
			b.WriteString("k:\n")
		}
		b.WriteString(strings.Repeat("  ", depth+4))
		b.WriteString("v\n")

		_, err := load(t, b.String())
		if err == nil {
			t.Fatal("a 200-deep service config was accepted")
		}
		assertClassifiedAndSafe(t, err)
	})

	t.Run("very large scalar", func(t *testing.T) {
		// Under the 1 MiB file bound, so the bound is not what refuses it. What
		// refuses it is the host grammar, and the point is that a 900 KiB value
		// does not make the message 900 KiB long.
		huge := strings.Repeat("a", 900*1024)
		_, err := load(t, "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: \""+huge+" \"\n")
		if err == nil {
			t.Fatal("a 900 KiB host containing a space was accepted")
		}
		assertClassifiedAndSafe(t, err)
		if n := len(err.Error()); n > 4096 {
			t.Errorf("the error message is %d bytes; a message must not carry the "+
				"document back to the operator", n)
		}
	})

	t.Run("very large service config node", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.example.com\n    config:\n")
		for i := range 20000 {
			b.WriteString("      k")
			b.WriteString(strings.Repeat("0", 1))
			b.WriteString(itoa(i))
			b.WriteString(": v\n")
		}
		_, err := load(t, b.String())
		if err == nil {
			t.Fatal("a 20,000-key service config was accepted; redis defines no fields")
		}
		assertClassifiedAndSafe(t, err)
	})
}

// itoa avoids importing strconv for one call in a table.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
