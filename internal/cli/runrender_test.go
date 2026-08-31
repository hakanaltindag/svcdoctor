package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// Phase 9.1C sections 20 to 23: what the renderers do with awkward but legal
// values, and how the two output modes relate.

// awkwardHosts are values the host grammar actually permits.
//
// checkHostSyntax refuses only whitespace and control characters, because
// everything else is a host *semantics* question that internal/probe owns. So
// these are all accepted, they all reach a report, and they all reach a
// terminal — which makes them the real adversarial set rather than a
// hypothetical one.
func awkwardHosts() []struct{ name, host string } {
	return []struct{ name, host string }{
		{"unicode", "münchen-db.example.com"},
		{"cjk", "データベース.example.com"},
		{"emoji", "db-🔐.example.com"},
		{"double quotes", `db"quoted".example.com`},
		{"single quotes", "db'quoted'.example.com"},
		{"brackets", "db[0].example.com"},
		{"braces", "db{0}.example.com"},
		{"backslash", `db\node.example.com`},
		{"percent verbs", "db-%s-%d-%v.example.com"},
		{"ansi-looking but printable", "db-[31m-red.example.com"},
		{"backtick", "db`tick`.example.com"},
		{"long at the identifier boundary", strings.Repeat("a", 60) + ".example.com"},
	}
}

// TestMTS15TheTerminalSurvivesEveryLegalValue is section 20.
//
// # What is asserted, and what deliberately is not
//
// The renderer is required to keep its own structure intact: every line it emits
// stays one line, and no control character reaches the terminal. It is *not*
// required to rewrite the operator's values, because it does not sanitize and
// nothing upstream asked it to — the defence is that a control character cannot
// get this far, which the test below proves separately.
func TestMTS15TheTerminalSurvivesEveryLegalValue(t *testing.T) {
	for _, tc := range awkwardHosts() {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, fmt.Sprintf(`
version: 1
targets:
  - id: awkward-target
    type: redis
    host: %q
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
`, tc.host))

			got := runCLI(t, context.Background(), "run", "--config", path)
			if got.stdout == "" {
				t.Fatalf("no output; exit %d, stderr %q", got.code, got.stderr)
			}

			assertNoControlCharacters(t, got.stdout)

			// Determinism: the same input renders the same frame every time.
			// Only the run's own measured timing may differ, so the frame is
			// compared by line *count* and by the lines that carry no timing.
			again := runCLI(t, context.Background(), "run", "--config", path)
			if a, b := lineCount(got.stdout), lineCount(again.stdout); a != b {
				t.Errorf("two runs produced %d and %d lines; the frame is not stable", a, b)
			}
			if got.code != again.code {
				t.Errorf("two runs exited %d and %d", got.code, again.code)
			}
		})
	}
}

// assertNoControlCharacters is the row-boundary property.
//
// A newline is the renderer's own row separator and is expected. Anything else
// that `unicode.IsControl` recognizes would move the cursor, change a colour or
// end a line somewhere the renderer did not intend.
func assertNoControlCharacters(t *testing.T, output string) {
	t.Helper()
	for index, r := range output {
		if r == '\n' {
			continue
		}
		if unicode.IsControl(r) {
			t.Errorf("a control character U+%04X reached the terminal at byte %d",
				r, index)
			return
		}
	}
}

func lineCount(s string) int { return strings.Count(s, "\n") }

// TestAControlCharacterCannotReachAReport is where the defence actually lives.
//
// The renderer does not sanitize, and this is why it does not have to: a control
// character is refused at two independent boundaries before any renderer sees
// it. Recording both matters, because removing either one alone would leave the
// property apparently intact.
//
//	config.checkHostSyntax    refuses a host holding one, at load time
//	domain.validateIdentifier refuses one in any identifier, at construction
//
// Broadening validation to make a renderer test convenient is exactly what
// Phase 9.1C section 20 forbids, so nothing here is relaxed to accommodate it.
func TestAControlCharacterCannotReachAReport(t *testing.T) {
	hostile := map[string]string{
		"escape":          "db\x1b[31m.example.com",
		"carriage return": "db\r.example.com",
		"newline":         "db\n.example.com",
		"tab":             "db\t.example.com",
		"NUL":             "db\x00.example.com",
		"bell":            "db\a.example.com",
	}

	for name, host := range hostile {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, fmt.Sprintf(`
version: 1
targets:
  - id: hostile
    type: redis
    host: %q
    tls:
      mode: disable
`, host))

			got := runCLI(t, context.Background(), "run", "--config", path)
			if got.code != ExitUsage {
				t.Errorf("exit = %d, want %d: a host holding a control character "+
					"must be refused before anything runs", got.code, ExitUsage)
			}
			if got.stdout != "" {
				t.Errorf("a refused host still produced output: %q", got.stdout)
			}
			assertNoControlCharacters(t, got.stderr)
		})
	}
}

// TestMTD07TheAggregateJSONIsValidAndRoundTrips is section 21.
//
// Marshalling is not enough: a document can be syntactically valid JSON and
// still lose meaning. So it is decoded and re-encoded, and the two generic
// structures must be deeply equal — which catches a value that survives
// encoding but not decoding.
func TestMTD07TheAggregateJSONIsValidAndRoundTrips(t *testing.T) {
	for _, tc := range awkwardHosts() {
		t.Run(tc.name, func(t *testing.T) {
			// Two targets on the same awkward host, so repeated values and
			// repeated pseudonyms are both in the document.
			path := writeConfig(t, fmt.Sprintf(`
version: 1
targets:
  - id: json-one
    type: redis
    host: %q
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
  - id: json-two
    type: redis
    host: %q
    port: 6380
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
`, tc.host, tc.host))

			for _, extra := range [][]string{nil, {"--shareable"}} {
				args := append([]string{"run", "--config", path, "--output", "json"}, extra...)
				got := runCLI(t, context.Background(), args...)

				if !json.Valid([]byte(got.stdout)) {
					t.Fatalf("the aggregate is not valid JSON: %q", got.stdout)
				}

				var first any
				if err := json.Unmarshal([]byte(got.stdout), &first); err != nil {
					t.Fatalf("decoding: %v", err)
				}
				reencoded, err := json.Marshal(first)
				if err != nil {
					t.Fatalf("re-encoding: %v", err)
				}
				var second any
				if err := json.Unmarshal(reencoded, &second); err != nil {
					t.Fatalf("re-decoding: %v", err)
				}
				if !reflect.DeepEqual(first, second) {
					t.Error("the aggregate does not survive a JSON round trip")
				}

				assertNoCredentialSurfaceInJSON(t, got.stdout)
			}
		})
	}
}

// assertNoCredentialSurfaceInJSON pins section 21's last clause.
func assertNoCredentialSurfaceInJSON(t *testing.T, document string) {
	t.Helper()
	for _, forbidden := range []string{
		"SecretRef", "secretRef", "credentialRef", "credentials",
		"password", "Password", "envName", "secretFile",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("the aggregate carries a credential surface named %q", forbidden)
		}
	}
}

// TestMTS16OnePseudonymTablePerRun is section 22.
//
// ADR 0074 section 8.1: a host appearing in two targets receives **one**
// pseudonym across the whole aggregate, because redaction preserves correlation
// while removing identity. Two different hosts must receive two.
//
// # Why this is a differential comparison rather than a count
//
// The obvious version counts host pseudonyms and expects two. It is wrong, and
// measuring it is how that was found: a report also names the **vantage**, which
// is a host and is pseudonymized like any other, so the count is three. Pinning
// three would then encode an assumption about the machine running the test —
// a vantage that resolves to an address rather than a name changes it again.
//
// So two runs are compared instead. They are identical except that one puts both
// targets on one host and the other puts them on two. Whatever the vantage
// contributes, it contributes equally to both, and the difference must be
// exactly one.
func TestMTS16OnePseudonymTablePerRun(t *testing.T) {
	render := func(secondHost string) string {
		path := writeConfig(t, fmt.Sprintf(`
version: 1
targets:
  - id: shared-one
    type: redis
    host: repeated.invalid
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
  - id: shared-two
    type: redis
    host: %s
    port: 6380
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
`, secondHost))

		got := runCLI(t, context.Background(), "run", "--config", path,
			"--output", "json", "--shareable")
		if got.stdout == "" {
			t.Fatalf("no aggregate; exit %d stderr %q", got.code, got.stderr)
		}
		return got.stdout
	}

	sameHost := render("repeated.invalid")
	twoHosts := render("different.invalid")

	shared := len(collectPseudonyms(sameHost))
	distinct := len(collectPseudonyms(twoHosts))

	if shared == 0 {
		t.Fatal("no host pseudonym appears at all, so this case proves nothing")
	}
	if distinct != shared+1 {
		t.Errorf("one host across two targets produced %d pseudonyms and two hosts "+
			"produced %d; the difference must be exactly 1, because a repeated host "+
			"receives one pseudonym and a second host receives its own",
			shared, distinct)
	}

	// The real names are gone from both.
	for _, document := range []string{sameHost, twoHosts} {
		for _, real := range []string{"repeated.invalid", "different.invalid"} {
			if strings.Contains(document, real) {
				t.Errorf("the shareable aggregate still carries the real host %q", real)
			}
		}
	}

	// Target identifiers are pseudonymized in declared order.
	for i, want := range []string{"target-001", "target-002"} {
		if !strings.Contains(twoHosts, want) {
			t.Errorf("target %d is not pseudonymized as %q", i+1, want)
		}
	}
	for _, real := range []string{"shared-one", "shared-two"} {
		if strings.Contains(twoHosts, real) {
			t.Errorf("the real target identifier %q survived redaction", real)
		}
	}
}

// collectPseudonyms extracts every host-NNN token from a document.
func collectPseudonyms(document string) []string {
	seen := map[string]bool{}
	for _, field := range strings.FieldsFunc(document, func(r rune) bool {
		return r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if strings.HasPrefix(field, "host-") {
			seen[field] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	return out
}

// TestPseudonymsAreDeterministicWithinARunAndNotAcrossRuns pins the frozen
// stability policy in both directions, because each half is a security property
// and they point opposite ways.
//
//	within one run   stable, so correlation survives and the document is useful
//	across two runs  no guarantee, deliberately
//
// A stable cross-run pseudonym would let someone holding two shared reports from
// the same environment correlate them, which is what redaction exists to
// prevent. So the second half asserts only that the *shape* is stable — not that
// the mapping is — and says why.
func TestPseudonymsAreDeterministicWithinARunAndNotAcrossRuns(t *testing.T) {
	path := writeConfig(t, `
version: 1
targets:
  - id: alpha
    type: redis
    host: alpha.invalid
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
  - id: beta
    type: redis
    host: beta.invalid
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
`)

	render := func() string {
		got := runCLI(t, context.Background(), "run", "--config", path,
			"--output", "json", "--shareable")
		if got.stdout == "" {
			t.Fatalf("no aggregate; exit %d", got.code)
		}
		return normalizeRunTiming(t, got.stdout)
	}

	if a, b := render(), render(); a != b {
		t.Errorf("two identical runs produced different shareable documents; "+
			"pseudonym assignment is not deterministic within a run:\n%s\n%s", a, b)
	}
}

// TestManyDistinctIdentitiesReceiveDistinctPseudonyms is section 22's collision
// requirement.
//
// A large deterministic set of distinct hosts must produce as many distinct
// pseudonyms. A collision would merge two real hosts into one apparent host,
// which is worse than revealing either: it invents a correlation that does not
// exist, and a reader has no way to notice.
//
// Differential for the same reason as the test above — the vantage contributes a
// pseudonym of its own, equally to both runs, so comparing them cancels it.
func TestManyDistinctIdentitiesReceiveDistinctPseudonyms(t *testing.T) {
	const targets = 64

	render := func(distinctHosts bool) string {
		doc := "version: 1\nrun:\n  concurrency: 8\ntargets:\n"
		for i := range targets {
			host := "shared.invalid"
			if distinctHosts {
				host = fmt.Sprintf("h%03d.invalid", i)
			}
			doc += fmt.Sprintf("  - id: t%03d\n    type: redis\n    host: %s\n"+
				"    port: %d\n    timeout: 3s\n    step_timeout: 2s\n"+
				"    tls:\n      mode: disable\n", i, host, 6379+i)
		}

		got := runCLI(t, context.Background(), "run", "--config", writeConfig(t, doc),
			"--output", "json", "--shareable")
		if got.stdout == "" {
			t.Fatalf("no aggregate; exit %d stderr %q", got.code, got.stderr)
		}
		return got.stdout
	}

	oneHost := render(false)
	manyHosts := render(true)

	base := len(collectPseudonyms(oneHost))
	if base == 0 {
		t.Fatal("no host pseudonym appears at all")
	}
	if got, want := len(collectPseudonyms(manyHosts)), base+targets-1; got != want {
		t.Errorf("%d distinct hosts produced %d pseudonyms, want %d; two real hosts "+
			"were merged into one", targets, got, want)
	}

	for i := range targets {
		if real := fmt.Sprintf("h%03d.invalid", i); strings.Contains(manyHosts, real) {
			t.Errorf("the real host %q survived redaction", real)
		}
	}
}

// TestMTS15ShareableNeverExposesWhatLocalAlreadyHid is section 23.
//
// The relationship between the two modes is one-directional: shareable may hide
// or pseudonymize *more*, and may never reveal anything the local document had
// already removed. That is asserted as a set relation rather than case by case,
// so a future field is covered without being enumerated.
//
// It also pins the part that must **not** differ: the diagnosis. Only
// representation changes between the modes — the same states, the same finding
// codes, the same counts and the same execution states.
func TestMTS15ShareableNeverExposesWhatLocalAlreadyHid(t *testing.T) {
	path := writeConfig(t, `
version: 1
targets:
  - id: local-one
    type: redis
    host: one.invalid
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
  - id: local-two
    type: postgres
    host: two.invalid
    timeout: 3s
    step_timeout: 2s
    tls:
      mode: disable
    credentials:
      username: someuser
    config:
      database: somedb
`)

	local := runCLI(t, context.Background(), "run", "--config", path, "--output", "json")
	shared := runCLI(t, context.Background(), "run", "--config", path,
		"--output", "json", "--shareable")

	if local.stdout == "" || shared.stdout == "" {
		t.Fatal("one of the two forms produced nothing")
	}
	if local.code != shared.code {
		t.Errorf("--shareable changed the exit code from %d to %d; redaction is a "+
			"representation, not a diagnosis", local.code, shared.code)
	}

	// Every finding code, execution state and status is identical. Redaction
	// removes identity; it does not re-diagnose.
	for _, field := range []string{"executionState", "status", "severity", "code"} {
		if a, b := valuesOf(t, local.stdout, field), valuesOf(t, shared.stdout, field); !reflect.DeepEqual(a, b) {
			t.Errorf("%s differs between the modes:\n local: %v\nshared: %v", field, a, b)
		}
	}

	// The one-directional property: no *identifying value* may appear in the
	// shareable form that is absent from the local one.
	//
	// The sweep is restricted to host-shaped tokens, and the restriction is the
	// interesting part. A whole-vocabulary comparison fails on things that are
	// supposed to differ — the output mode name, the `redactions` block redaction
	// adds, and the run's own measured timings — none of which is an identity.
	// Narrowing to dotted names keeps the check aimed at what redaction is for.
	for _, token := range distinctTokens(shared.stdout) {
		// Dotted, and beginning with a letter. The second condition excludes
		// measured durations — "676.625µs" is dotted and contains letters — which
		// are timings rather than identities and legitimately differ between two
		// runs of anything.
		if !strings.Contains(token, ".") || !unicode.IsLetter(rune(token[0])) {
			continue
		}
		if strings.HasPrefix(token, "host-") || strings.HasPrefix(token, "ip-") {
			// A pseudonym, which exists only in the shareable form by design.
			continue
		}
		if !strings.Contains(local.stdout, token) {
			t.Errorf("the shareable form introduced the host-shaped token %q, which "+
				"the local form does not contain", token)
		}
	}

	// And the values the local form legitimately carries are gone.
	//
	// The username is deliberately absent from this list: these targets fail at
	// DNS, so authentication is never attempted and no identity is recorded.
	// Asserting its removal here would assert the removal of something that was
	// never present. Identity redaction is owned by
	// internal/security/redaction/identity_test.go, where an identity exists.
	for _, identifying := range []string{
		"one.invalid", "two.invalid", "local-one", "local-two",
	} {
		if !strings.Contains(local.stdout, identifying) {
			t.Fatalf("%q is absent from the local form, so its removal proves nothing",
				identifying)
		}
		if strings.Contains(shared.stdout, identifying) {
			t.Errorf("%q survived into the shareable form", identifying)
		}
	}
}

// valuesOf collects every value of a named JSON field, anywhere in a document.
func valuesOf(t *testing.T, document, field string) []string {
	t.Helper()
	var parsed any
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	var out []string
	var walk func(any)
	walk = func(node any) {
		switch value := node.(type) {
		case map[string]any:
			// Keys are visited in sorted order so the collected slice is
			// comparable between two documents.
			for _, key := range sortedKeys(value) {
				if key == field {
					out = append(out, fmt.Sprint(value[key]))
				}
				walk(value[key])
			}
		case []any:
			for _, item := range value {
				walk(item)
			}
		}
	}
	walk(parsed)
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// distinctTokens splits a document into word-like tokens for the set comparison.
func distinctTokens(document string) []string {
	seen := map[string]bool{}
	for _, field := range strings.FieldsFunc(document, func(r rune) bool {
		return r != '-' && r != '_' && r != '.' &&
			!unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if len(field) >= 4 {
			seen[field] = true
		}
	}
	out := make([]string, 0, len(seen))
	for token := range seen {
		out = append(out, token)
	}
	return out
}
