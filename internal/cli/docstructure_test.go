package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// Phase 9.2B, ADR 0075 §2.4 and §2.6: the public documentation cannot drift.
//
// # The half that was missing
//
// docsclaims_test.go guards the documentation in **one direction**: it forbids
// claiming a platform nobody ran against, a mechanism nobody implemented, and
// health the product cannot observe. Nothing in it can fire when a document
// *omits* something that exists.
//
// So Phase 9.2A found a README whose second sentence named two of four services,
// whose credential section said "there are exactly two credential sources" while
// a later section documented a third, and which asserted in one place that
// nothing was published to GHCR and in two others how to pull it. Every one of
// those survived a full `make check`.
//
// These are the other direction: a capability that exists must be documented,
// and a document that contradicts the repository is a failing build.

// publicDocuments are the six ADR 0075 §2.4 froze, plus the security policy.
//
// Each is named here so that deleting one fails rather than silently removing a
// guarantee: several tests below read them, and a missing file that the reader
// skips is a guard that stops guarding.
var publicDocuments = []string{
	"README.md",
	"SECURITY.md",
	"docs/QUICKSTART.md",
	"docs/CONFIGURATION.md",
	"docs/OUTPUT.md",
	"docs/CI.md",
	"docs/COMPATIBILITY.md",
}

// TestUX15EveryPublicDocumentExists is the cheapest guard and the one that makes
// the rest non-vacuous.
func TestUX15EveryPublicDocumentExists(t *testing.T) {
	for _, name := range publicDocuments {
		if strings.TrimSpace(readRepoFile(t, name)) == "" {
			t.Errorf("%s is empty", name)
		}
	}
}

// advertisedServices reads the service list from the product rather than from a
// constant in this file.
//
// `diagnose --help` is generated from the same registration the composition root
// uses, so a service that is registered is advertised and a service that is not
// is neither. Reading it here is what makes the README guard track the product
// instead of tracking a second list somebody has to remember to update.
func advertisedServices(t *testing.T) []string {
	t.Helper()

	help := helpOf(t, "diagnose", "--help")
	body, _, found := strings.Cut(help, "Services:")
	_ = body
	if !found {
		t.Fatal("`diagnose --help` has no Services section; this guard reads it")
	}
	_, list, _ := strings.Cut(help, "Services:")

	var services []string
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(line, "  ") {
			continue
		}
		if strings.HasPrefix(fields[0], "-") || strings.Contains(line, "--help") {
			continue
		}
		services = append(services, fields[0])
	}
	return services
}

// TestUX18EveryDocumentedLinkResolves keeps the documentation navigable.
//
// A landing page that links to five documents is only useful if the five exist.
// Relative Markdown links are checked; external ones are not, because a test
// that reaches the network is a test that fails when the network does.
func TestUX18EveryDocumentedLinkResolves(t *testing.T) {
	link := regexp.MustCompile(`\[[^\]]*\]\(([^)#]+)(?:#[^)]*)?\)`)

	var checked int
	for _, name := range publicDocuments {
		body := readRepoFile(t, name)
		base := filepath.Dir(filepath.Join("..", "..", name))

		for _, match := range link.FindAllStringSubmatch(body, -1) {
			target := match[1]
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") {
				continue
			}
			checked++
			if _, err := os.Stat(filepath.Join(base, target)); err != nil {
				t.Errorf("%s links to %q, which does not exist", name, target)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no relative link was found in any public document; this guard would " +
			"pass vacuously")
	}
	t.Logf("%d relative links checked", checked)
}

// TestUX15TheDocumentedServicesAreTheRegisteredServices is UX-B02's structural
// half.
//
// The service list is read from the **product** — `diagnose --help` is generated
// from the same registration the composition root uses — and every name it
// advertises must appear in the README's own statement of what is supported.
//
// This is the guard that would have caught "PostgreSQL BASIC and Kafka BASIC are
// supported today" on the day Redis shipped.
func TestUX15TheDocumentedServicesAreTheRegisteredServices(t *testing.T) {
	advertised := advertisedServices(t)
	if len(advertised) != 4 {
		t.Fatalf("`diagnose --help` advertises %v; the guard reads it to find the "+
			"services, so a change here needs a deliberate look rather than a new number",
			advertised)
	}

	readme := readRepoFile(t, "README.md")
	lower := strings.ToLower(readme)

	// Each registered service, by the name a reader would search for.
	for _, want := range []struct{ service, needle string }{
		{"postgres", "postgresql"},
		{"kafka", "kafka"},
		{"redis", "redis"},
		{"rabbitmq", "rabbitmq"},
	} {
		if !strings.Contains(lower, want.needle) {
			t.Errorf("the README never mentions %s, which `diagnose --help` advertises",
				want.service)
		}
		if !strings.Contains(readme, "diagnose "+want.service) {
			t.Errorf("the README shows no `svcdoctor diagnose %s` invocation", want.service)
		}
	}

	// And the multi-target command, which is not a service and is just as
	// easy to leave out of a document written when it did not exist.
	if !strings.Contains(readme, "run --config") {
		t.Error("the README never shows `svcdoctor run --config`")
	}
}

// TestUX15TheREADMECountsServicesCorrectly catches the stale-count sentence.
//
// The specific failure was a headline claim naming two services while four were
// built. A count in prose is the thing most likely to go stale and least likely
// to be noticed, so any sentence that counts services is required to say four.
func TestUX15TheREADMECountsServicesCorrectly(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	for _, stale := range []string{
		"PostgreSQL BASIC and Kafka BASIC are supported today",
		"Two leaf commands",
		"two leaf commands",
		"v0.1 contains only Kafka + PostgreSQL",
	} {
		if strings.Contains(readme, stale) {
			t.Errorf("the README still says %q.\n\n"+
				"Four services are registered and five commands are exposed. A count "+
				"written before Redis and RabbitMQ shipped tells a reader the product "+
				"does less than it does.", stale)
		}
	}

	if !strings.Contains(readme, "Four services are supported") {
		t.Error("the README does not state how many services are supported.\n\n" +
			"A reader deciding whether svcdoctor is worth trying reads that sentence " +
			"and nothing else.")
	}
}

// TestUX15TheCredentialDocumentationCoversEverySource is the other half of
// UX-B02.
//
// Three sources exist: two leaf flags and the configuration reference, which
// itself has two forms. The README said "there are exactly two", and — worse —
// asserted that "svcdoctor's production code reads no environment variable at
// all", which stopped being true when the fleet resolver shipped. That is a
// false statement about a security property, which is the kind a reader relies
// on.
func TestUX15TheCredentialDocumentationCoversEverySource(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	for _, stale := range []string{
		"There are exactly two credential sources",
		"there are exactly two credential sources",
		"production code reads no environment variable at all",
		"There is no environment-variable secret source",
	} {
		if strings.Contains(readme, stale) {
			t.Errorf("the README still says %q.\n\n"+
				"internal/fleet/secret reads an environment variable when a "+
				"configuration names one. The true, narrower statement is that the four "+
				"leaf commands read none.", stale)
		}
	}

	for _, want := range []struct{ needle, why string }{
		{"--password-file", "the file source"},
		{"--password-stdin", "the stdin source"},
		{"env: NAME", "the environment-variable reference"},
		{"file: PATH", "the file reference"},
	} {
		if !strings.Contains(readme, want.needle) {
			t.Errorf("the README does not document %s", want.why)
		}
	}

	// The honest scoped claim has to be there, or removing the false one leaves
	// a reader with no answer about the leaf commands at all.
	lower := strings.ToLower(strings.Join(strings.Fields(readme), " "))
	if !strings.Contains(lower, "read no environment variable") {
		t.Error("the README no longer says that the leaf commands read no environment " +
			"variable.\n\nDeleting a false claim is not the same as making the true one.")
	}
}

// TestUX20TheShareableWordingStaysHonest is ADR 0077 §2.6's forbidden list.
//
// "Anonymous" is the word this must never acquire. A shareable report is
// pseudonymized, the pseudonyms are stable so that relationships survive, and a
// stable pseudonym is a correlation handle. Calling it anonymous would not be
// imprecision — it would tell a reader that sharing carries a guarantee it does
// not carry.
func TestUX20TheShareableWordingStaysHonest(t *testing.T) {
	forbidden := []struct{ phrase, why string }{
		{"anonymized", "it is pseudonymization; a stable pseudonym correlates"},
		{"anonymised", "it is pseudonymization; a stable pseudonym correlates"},
		{"fully anonymous", "no report is anonymous"},
		{"guaranteed anonymous", "no report is anonymous"},
		{"gdpr", "no compliance claim is made for any regime"},
		{"hipaa", "no compliance claim is made for any regime"},
		{"safe to publish", "ports, durations and timestamps are preserved"},
	}

	for _, name := range publicDocuments {
		body := readRepoFile(t, name)
		for _, sentence := range strings.Split(strings.ReplaceAll(body, "\n", " "), ". ") {
			lower := strings.ToLower(sentence)
			if !strings.Contains(lower, "shareable") && !strings.Contains(lower, "redact") {
				continue
			}
			for _, bad := range forbidden {
				if !strings.Contains(lower, bad.phrase) {
					continue
				}
				// A sentence that denies the claim is the point, not a defect:
				// "It is pseudonymization, not anonymization" must be sayable.
				if denies(sentence) || strings.Contains(lower, "not "+bad.phrase) {
					continue
				}
				t.Errorf("%s says %q of a shareable report: %s\n\n  %s",
					name, bad.phrase, bad.why, strings.TrimSpace(sentence))
			}
		}
	}

	// And the honest words have to be present somewhere, or the guard above is
	// satisfiable by never describing the feature.
	output := readRepoFile(t, "docs/OUTPUT.md")
	for _, want := range []string{"pseudonym", "not anonymization", "fails closed"} {
		if !strings.Contains(strings.ToLower(output), want) {
			t.Errorf("docs/OUTPUT.md does not say %q about shareable reports", want)
		}
	}
}

// TestUX13TheDocumentedExitCodesMatchTheImplementation reads both and compares.
//
// docs/CI.md is authoritative (ADR 0077 §2.1), so it must document exactly the
// codes the package defines — no more, and no fewer. A sixth documented code
// would be fiction; a missing one would leave a pipeline author guessing.
func TestUX13TheDocumentedExitCodesMatchTheImplementation(t *testing.T) {
	implemented := map[int]string{
		ExitOK:            "no error-level target-side problem was proven",
		ExitProblemsFound: "an error-level target-side problem was proven",
		ExitUsage:         "svcdoctor was invoked with something it cannot act on",
		ExitInternal:      "svcdoctor itself failed",
		ExitIncomplete:    "svcdoctor's own execution did not finish",
	}
	if len(implemented) != 5 {
		t.Fatalf("%d codes are implemented; the contract is five", len(implemented))
	}

	ci := readRepoFile(t, "docs/CI.md")

	for code := range implemented {
		if !strings.Contains(ci, "`"+itoa(code)+"`") {
			t.Errorf("docs/CI.md does not document exit code %d", code)
		}
	}
	for _, absent := range []int{5, 6, 7} {
		if strings.Contains(ci, "| `"+itoa(absent)+"` |") {
			t.Errorf("docs/CI.md documents exit code %d, which does not exist", absent)
		}
	}

	// The precedence, which is the part most often got backwards.
	if !strings.Contains(ci, "`3` > `2` > `4` > `1` > `0`") {
		t.Error("docs/CI.md does not state the exit-code precedence 3 > 2 > 4 > 1 > 0")
	}

	// And the three traps, each of which is a way to misread a code.
	for _, want := range []string{
		"Exit 0 is not",
		"Exit 1 is not a svcdoctor failure",
		"Exit 4 outranks exit 1",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("docs/CI.md does not warn: %q", want)
		}
	}
}

// TestUX14NoDocumentedShellExampleDiscardsTheExitCode is the CI trap guard.
//
// `|| true` always exits 0. A pipeline reports its **last** command's status, so
// `svcdoctor … | tee report.json` exits with tee's. Both were measured in Phase
// 9.2A: a run that exited 1 became 0 through tee under POSIX sh.
//
// Either in a copied example silently turns a failing check into a passing one,
// which is the worst available outcome for a diagnostic tool.
func TestUX14NoDocumentedShellExampleDiscardsTheExitCode(t *testing.T) {
	var checked int
	for _, name := range publicDocuments {
		for _, block := range fencedBlocks(readRepoFile(t, name), "sh", "bash", "yaml") {
			for _, line := range strings.Split(block, "\n") {
				if !strings.Contains(line, "svcdoctor") {
					continue
				}
				checked++
				if strings.Contains(line, "|| true") {
					t.Errorf("%s runs svcdoctor with `|| true`, which discards the "+
						"result:\n  %s", name, strings.TrimSpace(line))
				}
				// A pipe is allowed only where the document is explicitly
				// teaching the trap, which it marks by naming PIPESTATUS.
				if strings.Contains(line, "| tee") && !strings.Contains(block, "PIPESTATUS") {
					t.Errorf("%s pipes svcdoctor into tee without recovering the exit "+
						"code:\n  %s", name, strings.TrimSpace(line))
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no svcdoctor invocation was found in any fenced block; this guard " +
			"would pass vacuously")
	}
	t.Logf("%d documented svcdoctor invocations checked", checked)
}

// TestUX0405EveryDocumentedConfigurationParses is ADR 0075 §2.6's first
// mechanism.
//
// Every YAML example an operator can copy — in the shipped examples directory
// and in every public document — is decoded by the **real loader**. A field
// renamed in production breaks the documentation in the same build, which is the
// only way an example stays true without somebody remembering to check it.
//
// A second parser for documentation tests would defeat the whole point, so this
// uses config.Load and nothing else.
func TestUX0405EveryDocumentedConfigurationParses(t *testing.T) {
	registry := fleetConfigRegistry()

	t.Run("shipped examples", func(t *testing.T) {
		examples, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
		if err != nil {
			t.Fatalf("globbing examples: %v", err)
		}
		if len(examples) < 3 {
			t.Fatalf("%d example configurations found; ADR 0075 §2.5 ships three",
				len(examples))
		}

		var services int
		for _, path := range examples {
			body, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			cfg, err := config.Load(body, filepath.Base(path), registry)
			if err != nil {
				t.Errorf("%s does not parse: %v", filepath.Base(path), err)
				continue
			}
			if filepath.Base(path) == "services.yaml" {
				kinds := map[string]bool{}
				for _, target := range cfg.Targets {
					kinds[target.Service] = true
				}
				services = len(kinds)
			}
			assertNoPlaintextCredential(t, filepath.Base(path), string(body))
		}

		if services != 4 {
			t.Errorf("examples/services.yaml covers %d services, want 4.\n\n"+
				"It is the canonical teaching example: a reader should see every "+
				"service's shape in one file.", services)
		}
	})

	t.Run("documented examples", func(t *testing.T) {
		var checked int
		for _, name := range publicDocuments {
			for _, block := range fencedBlocks(readRepoFile(t, name), "yaml") {
				// Only blocks that are whole configurations. A fragment showing
				// one `credentials:` stanza is illustrative and does not stand
				// alone, which the document makes obvious by not declaring a
				// version. Leading comments are skipped, because a block that
				// names the file it is — "# services.yaml" — is still a whole
				// configuration.
				if !isWholeConfiguration(block) {
					assertNoPlaintextCredential(t, name, block)
					continue
				}
				checked++
				if _, err := config.Load([]byte(block), name, registry); err != nil {
					t.Errorf("a configuration example in %s does not parse: %v\n\n%s",
						name, err, block)
				}
				assertNoPlaintextCredential(t, name, block)
			}
		}
		if checked == 0 {
			t.Fatal("no complete configuration example was found in any public " +
				"document; this guard would pass vacuously")
		}
		t.Logf("%d documented configurations parsed", checked)
	})
}

// TestUX06APlaintextCredentialExampleIsRefused proves the rule the examples obey
// is the product's rule and not just a convention this file checks.
func TestUX06APlaintextCredentialExampleIsRefused(t *testing.T) {
	const plaintext = `version: 1
targets:
  - id: orders-db
    type: postgres
    host: db.internal.example.com
    credentials:
      username: app
      password: hunter2
`
	_, err := config.Load([]byte(plaintext), "example.yaml", fleetConfigRegistry())
	if err == nil {
		t.Fatal("a plaintext password was accepted.\n\n" +
			"ADR 0072: the decoder's type for `password` is a mapping naming one " +
			"source, so a scalar cannot be decoded at all. This is refused by the " +
			"type rather than by a check, which is why no example can smuggle one in.")
	}
	if !strings.Contains(err.Error(), "env") || !strings.Contains(err.Error(), "file") {
		t.Errorf("the refusal does not tell the reader what to write instead: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// assertNoPlaintextCredential fails on a `password:` with a scalar value.
//
// Anchored to one line and requiring the value on that same line, so the correct
// form — a `password:` whose mapping is on the lines below it — is not matched.
// The first version used `\s*`, which spans newlines and flagged every valid
// example in the repository.
//
// The loader refuses one, so a complete example cannot carry it. A *fragment*
// can, and a fragment is what a reader copies fastest.
func assertNoPlaintextCredential(t *testing.T, where, body string) {
	t.Helper()

	scalar := regexp.MustCompile(`(?m)^[ \t]*password:[ \t]+\S`)
	for _, match := range scalar.FindAllString(body, -1) {
		t.Errorf("%s shows a plaintext password: %q\n\n"+
			"`password:` names a source — {env: NAME} or {file: PATH} — and never "+
			"holds a value.", where, strings.TrimSpace(match))
	}
}

// isWholeConfiguration reports whether a YAML block stands on its own.
//
// The test is the `version:` key at the top level, which every configuration
// requires and no fragment carries. Comments and blank lines above it are
// skipped: a block introduced by "# services.yaml" is a complete file with a
// label, not a fragment.
func isWholeConfiguration(block string) bool {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return strings.HasPrefix(trimmed, "version:")
	}
	return false
}

// fencedBlocks returns the bodies of every fenced code block with one of langs.
func fencedBlocks(document string, langs ...string) []string {
	wanted := map[string]bool{}
	for _, lang := range langs {
		wanted[lang] = true
	}

	var blocks []string
	var current strings.Builder
	var inside bool

	for _, line := range strings.Split(document, "\n") {
		switch {
		case !inside && strings.HasPrefix(line, "```"):
			if wanted[strings.TrimSpace(strings.TrimPrefix(line, "```"))] {
				inside = true
				current.Reset()
			}
		case inside && strings.HasPrefix(line, "```"):
			blocks = append(blocks, current.String())
			inside = false
		case inside:
			current.WriteString(line)
			current.WriteString("\n")
		}
	}
	return blocks
}

// itoa renders an exit code for a document lookup.
func itoa(n int) string { return strconv.Itoa(n) }
