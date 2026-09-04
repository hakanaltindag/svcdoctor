package cli

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// The capability-claim audit for the two documents an operator reads before
// running anything: the README and `--help`.
//
// # Why this exists
//
// Phase 6.5's mutation matrix planted two sentences and nothing failed:
// a README that says literal IPv4/IPv6 targets are supported, and an opening
// claim that names Confluent Cloud, AWS MSK and Redpanda as supported. Both are
// false, both are the kind of sentence that gets written in a hurry before a
// release, and neither is reachable from any test that reads Go code.
//
// The cost of each is asymmetric with its size. An operator who believes
// `--host` accepts an address gets a run whose transport diagnosis is right and
// whose `dns.lookup` PASS and hostname-resolution wording are not — the defect
// is reproduced and recorded in docs/BACKLOG.md, and the honest position until
// it is decided is that the capability is not advertised. An operator who
// believes a managed provider is supported has been told svcdoctor validated
// something against an implementation it has never run against; the Kafka
// fixture is Apache Kafka, and protocol similarity is not evidence.
//
// # What these do not do
//
// They do not read prose for meaning. Each pins one checkable structural fact,
// so ordinary editing is free and the two specific reversals are not.

// managedProviders are the names that would imply provider compatibility.
//
// Both services, because the claim is equally unproven on either side and a
// README does not separate them.
var managedProviders = []string{
	"Confluent", "MSK", "Event Hubs",
	"RDS", "Aurora", "Cloud SQL", "Azure Database",
}

// Redpanda is deliberately absent from the list above, and moved to its own rule
// below, because it is the one name that stopped being unproven.
//
// Phase 7.0b committed `test/integration/redpanda/` against a pinned
// v25.1.9 and the whole BASIC journey passes there over `PLAIN` and
// `SCRAM-SHA-256`. A blanket ban would now forbid a true sentence, and a guard
// that forbids the truth gets deleted rather than obeyed.
//
// What replaces it is narrower rather than weaker: the claim must carry the
// version it was measured at, and the three ways of widening it are named.
// See TestTheREADMEsRedpandaClaimStaysNarrow.

// denials are the words that mark a line as recording an absence rather than
// making a claim.
//
// Matched as whole words against a line stripped of Markdown emphasis, because
// the README writes "are **not** implemented" and a substring search for "not "
// misses it — which is how the first version of this guard failed on truthful
// prose.
var denials = map[string]bool{
	"not": true, "no": true, "never": true, "none": true,
	"nothing": true, "deferred": true, "unproven": true, "without": true,
	// "neither … nor" is the natural way to deny two mechanisms at once, which
	// is exactly what release notes do when they account for MSK's SCRAM-SHA-512
	// and AWS_MSK_IAM in one sentence. Omitting it made a correct denial read as
	// an overclaim.
	//
	// This completes the negation vocabulary rather than widening the guard:
	// every word here can only appear in a statement that negates something, so
	// no positive claim gains an exemption. TestTheDocsClaimGuardsCanFail holds
	// that line — an actual support claim contains none of these.
	"neither": true, "nor": true,
	// "unclaimed" is the release notes' way of listing the managed platforms
	// nobody has run against — "Redpanda Cloud, Confluent Cloud, AWS MSK … remain
	// unclaimed" is a denial of exactly the thing these guards forbid claiming,
	// and it read as an overclaim because the vocabulary had no word for it.
	// Found when the guards followed `releaseNotes` forward to v0.4.0.
	//
	// It obeys the same rule as the rest: a sentence claiming support cannot
	// contain it.
	"unclaimed": true,
}

// TestTheREADMENeverClaimsManagedCompatibility keeps provider names where they
// belong.
//
// A provider may be named only while the README is denying support for it or
// listing it as future work. Anywhere else — an opening summary, a feature
// table, an example — naming one asserts a compatibility nothing has measured.
//
// The Roadmap section is exempt as a whole, because its entire content is work
// not yet done and requiring a denial word on each of its bullets would be
// noise.
func TestTheREADMENeverClaimsManagedCompatibility(t *testing.T) {
	for _, name := range unqualifiedClaimDocuments {
		t.Run(name, func(t *testing.T) { assertNoManagedCompatibilityClaim(t, name) })
	}

	// And the backlog item stays visible in the README, so the absence is
	// recorded rather than merely true. This half is README-specific: it is a
	// statement about future work, which release notes have no reason to carry.
	if !strings.Contains(readRepoFile(t, "README.md"), "managed-service protocol compatibility") {
		t.Error("the README no longer lists managed-service compatibility as future work")
	}
}

// assertNoManagedCompatibilityClaim was the body of the test above, which read
// only the README. The release notes now *are* the GitHub Release body, so a
// provider named there reaches more readers than one named in the README ever
// did; scoping this rule to a single file was an accident of where it was first
// needed, not a decision.
func assertNoManagedCompatibilityClaim(t *testing.T, name string) {
	t.Helper()

	// Claim units, not lines. Two defects, learned in that order.
	//
	// Sentence by sentence, because one README line carries both the opening
	// capability claim and an unrelated "No APM ... is required" beside it, and a
	// line-level denial check let a planted "including Confluent Cloud, AWS MSK
	// and Redpanda" ride on that neighbouring "No".
	//
	// And *across* lines, because Markdown wraps prose to a column: the release
	// notes' "Redpanda Cloud, Confluent Cloud, AWS MSK … remain unclaimed" puts
	// the providers on one line and the denial on the next, and a line-wise walk
	// saw the first half alone. The sibling guards already used `claimUnits` for
	// exactly this; this one did not, and it went unnoticed until the guards
	// followed `releaseNotes` forward to a document whose denial wraps.
	for _, sentence := range claimUnits(docOutsideRoadmap(t, name)) {
		for _, provider := range managedProviders {
			if !strings.Contains(sentence, provider) || denies(sentence) {
				continue
			}
			t.Errorf("%s names %s outside the Roadmap without denying "+
				"support:\n  %s\n\n"+
				"Kafka BASIC is validated against Apache Kafka and PostgreSQL "+
				"BASIC against PostgreSQL and pgBouncer. Protocol similarity is "+
				"not evidence, and managed-service compatibility is an open "+
				"backlog item.", name, provider, sentence)
		}
	}
}

// TestTheDocsRecordIPLiteralSupport is the inverse of the guard Phase 6.5 held
// here, and the inversion is the point.
//
// Until Phase 6.7 the contract was that `--host` expects a name that resolves,
// because a literal produced a `dns.lookup` PASS for work that did not happen.
// The graph-shape decision was taken (ADR 0059), a literal now performs and
// records no resolution, and the capability is real — so the documents must say
// so, and this fails if that sentence disappears.
//
// The guard did not become weaker. It kept its shape and changed sides: the
// claim it used to forbid is now the claim it requires, and the claim it now
// forbids — scoped IPv6 — is the one thing this phase deliberately did not
// implement.
func TestTheDocsRecordIPLiteralSupport(t *testing.T) {
	docs := map[string]string{"README.md": readRepoFile(t, "README.md")}
	for _, service := range []string{"kafka", "postgres"} {
		h := newHarness(app.Result{}, nil)
		if code := h.run("diagnose", service, "--help"); code != ExitOK {
			t.Fatalf("`diagnose %s --help` exit = %d", service, code)
		}
		docs[service+" help"] = h.stdout.String()
	}

	for where, text := range docs {
		// Whitespace is collapsed first: help text is wrapped to a column, so a
		// phrase can be split across two lines without changing what it says.
		lower := strings.Join(strings.Fields(strings.ToLower(text)), " ")
		if !strings.Contains(lower, "ipv4 or ipv6 address") {
			t.Errorf("%s no longer says that --host accepts an address literal", where)
		}
		assertNoScopedIPv6Claim(t, where, text)
	}
}

// TestTheREADMEStillDeniesWhatWasNotImplemented keeps the boundary of the
// capability honest.
//
// First-class literal support is not scoped-IPv6 support, and a README that
// blurred the two would promise something `probe.ParseHost` refuses outright.
func TestTheREADMEStillDeniesWhatWasNotImplemented(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	if !strings.Contains(readme, "no scoped IPv6") {
		t.Error("the README's `Not in v0.1` list no longer records that a zoned " +
			"IPv6 literal is refused")
	}
}

// assertNoScopedIPv6Claim fails on any sentence offering a zone identifier as
// valid input.
//
// A zone is a vantage-local interface name with no decided representation in the
// evidence subject, the credential binding key, the TLS identity or the
// pseudonym namespace, and probe.ParseHost refuses one. Advertising it would
// promise a capability the code declines to have.
func assertNoScopedIPv6Claim(t *testing.T, where, text string) {
	t.Helper()

	claims := []string{
		"scoped ipv6 is supported",
		"zone identifier is supported",
		"including a zone",
		"with a zone identifier",
		"fe80::1%en0 is supported",
		"link-local with zone",
	}
	lower := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	for _, claim := range claims {
		if strings.Contains(lower, claim) {
			t.Errorf("%s offers %q as valid input for a target.\n\n"+
				"probe.ParseHost refuses a zoned literal, and the zone has no decided "+
				"representation in the subject, the credential key, the TLS identity "+
				"or the pseudonym namespace. Support is deferred; see ADR 0059.",
				where, claim)
		}
	}
}

// TestTheDocsClaimGuardsCanFail proves neither guard is vacuous.
func TestTheDocsClaimGuardsCanFail(t *testing.T) {
	// The exact line mutation M29 planted: a capability claim followed by an
	// unrelated denial. Split correctly, the first sentence is not a denial.
	planted := "**PostgreSQL BASIC and Kafka BASIC are supported today, including " +
		"Confluent Cloud, AWS MSK and Redpanda.** No APM, OpenTelemetry collector,"
	sentences := claimSentences(planted)
	if len(sentences) < 2 {
		t.Fatalf("the claim and the denial beside it were not separated: %q", sentences)
	}
	if denies(sentences[0]) {
		t.Errorf("a sentence claiming managed support reads as a denial: %q", sentences[0])
	}
	if !strings.Contains(sentences[0], "Confluent") {
		t.Errorf("the claim sentence lost its provider name: %q", sentences[0])
	}
	if !denies("`AWS_MSK_IAM` and mTLS client-certificate authentication are **not** implemented.") {
		t.Error("the production denial is not recognized as one")
	}

	fake := &testing.T{}
	assertNoScopedIPv6Claim(fake, "planted",
		"`--host` accepts a link-local address with a zone identifier.")
	if !fake.Failed() {
		t.Error("the guard does not flag a planted scoped-IPv6 claim")
	}
}

// claimSentences splits one Markdown line into the sentences a reader parses.
//
// Emphasis and code spans are removed first, so "supported today.** No APM"
// becomes two sentences rather than one — which is the whole point, since the
// second one's "No" must not exempt the first one's claim.
func claimSentences(line string) []string {
	stripped := strings.Map(func(r rune) rune {
		if r == '*' || r == '`' {
			return -1
		}
		return r
	}, line)

	var out []string
	for _, s := range strings.Split(stripped, ". ") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// denies reports whether a sentence is recording an absence.
//
// Markdown emphasis and code spans are stripped first, and the remainder is
// matched word by word: "**not**" and "`no`" are denials, and a provider name
// that happens to contain one of these letter sequences is not.
func denies(line string) bool {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '*', '`', '_':
			return -1
		case ',', '.', ';', ':', '(', ')', '"':
			return ' '
		}
		return r
	}, strings.ToLower(line))

	for _, word := range strings.Fields(cleaned) {
		if denials[word] {
			return true
		}
	}
	return false
}

// --- insecure-mode claim discipline -----------------------------------------

// The `--tls-insecure` entry is audited for the same reason the provider names
// are: it is a sentence an operator reads *before* running anything, and getting
// it wrong changes what they believe a passing run proved.
//
// Phase 6.8A's mutation matrix planted a shortened entry — `--tls-insecure  skip
// TLS verification` — and nothing failed. It is true and it is not enough: it
// leaves an operator to infer what a passing TLS row then means, and the
// available inference is the wrong one.

// insecureEntryMustState are the facts the flag's own help entry has to carry.
//
// Structural, not prose: each is one lowercase substring, so ordinary rewording
// is free and dropping a fact is not.
var insecureEntryMustState = []struct {
	fact, substring string
}{
	{"what the handshake still proves", "encrypted"},
	{"that identity is not established", "who answered"},
	{"that no chain was validated", "no chain was validated"},
	{"the credential consequence", "withheld"},
	{"that it is never automatic", "never automatic"},
}

// TestBothHelpTextsExplainInsecureSemantics closes the surviving mutation.
//
// The two services share the entry verbatim, and both are checked, because the
// defect ADR 0060 closed was one contract held in two places that disagreed.
func TestBothHelpTextsExplainInsecureSemantics(t *testing.T) {
	for _, service := range []string{"postgres", "kafka"} {
		t.Run(service, func(t *testing.T) {
			entry := insecureHelpEntry(t, service)
			for _, want := range insecureEntryMustState {
				if !strings.Contains(entry, want.substring) {
					t.Errorf("the --tls-insecure entry does not state %s "+
						"(looked for %q).\n\nAn operator reads this before deciding to "+
						"disable verification. An entry that says only what the flag "+
						"switches off leaves them to infer what a passing TLS row then "+
						"proves, and the available inference is the wrong one "+
						"(ADR 0060 section 7).\n\nentry:\n%s",
						want.fact, want.substring, entry)
				}
			}
		})
	}
}

// TestNoDocumentSaysInsecureTLSIsVerified is the overclaim direction.
//
// These are the phrasings that would collapse *encrypted* into *authenticated
// peer*, which is the one thing `--tls-insecure` must never be described as.
func TestNoDocumentSaysInsecureTLSIsVerified(t *testing.T) {
	forbidden := []string{
		"verified but insecure", "insecure but verified",
		"still verifies", "verification still",
		"securely connected", "authenticated peer",
		"tls verified", "peer verified",
	}

	documents := map[string]string{"README.md": readRepoFile(t, "README.md")}
	for _, service := range []string{"postgres", "kafka"} {
		documents[service+" --help"] = helpText(t, service)
	}

	for name, text := range documents {
		lower := strings.Join(strings.Fields(strings.ToLower(text)), " ")
		for _, phrase := range forbidden {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s contains %q; an unverified handshake proves the channel "+
					"is encrypted and nothing about who answered (ADR 0060 section 7)",
					name, phrase)
			}
		}
	}
}

// TestTheInsecureClaimGuardCanFail proves the guard above is not vacuous.
func TestTheInsecureClaimGuardCanFail(t *testing.T) {
	if strings.Contains("  --tls-insecure            skip TLS verification",
		"who answered") {
		t.Fatal("the fixture is not the shortened entry the mutation planted")
	}
	for _, want := range insecureEntryMustState {
		if want.substring == "" {
			t.Error("an empty substring would match everything")
		}
	}
}

// insecureHelpEntry returns the `--tls-insecure` block of one service's help,
// lowercased, from the flag name to the start of the next flag or section.
func insecureHelpEntry(t *testing.T, service string) string {
	t.Helper()

	var entry []string
	collecting := false
	for _, line := range strings.Split(helpText(t, service), "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "--tls-insecure"):
			collecting = true
		case collecting && (strings.TrimSpace(line) == "" ||
			strings.HasPrefix(strings.TrimSpace(line), "--")):
			collecting = false
		}
		if collecting {
			entry = append(entry, strings.TrimSpace(line))
		}
	}
	if len(entry) == 0 {
		t.Fatalf("%s --help has no --tls-insecure entry at all", service)
	}
	return strings.ToLower(strings.Join(entry, " "))
}

// helpText captures one service's help exactly as an operator sees it.
func helpText(t *testing.T, service string) string {
	t.Helper()
	h := newHarness(app.Result{}, nil)
	if code := h.run("diagnose", service, "--help"); code != ExitOK {
		t.Fatalf("%s --help exited %d", service, code)
	}
	return h.stdout.String()
}

// --- the compatibility document ---------------------------------------------

// docs/COMPATIBILITY.md is the one document where provider names legitimately
// appear beside a verdict, so it is the one document where an overclaim is both
// easiest to write and hardest to notice. These guard the two ways it can lie.

// realTestedPlatforms is the complete set of platforms svcdoctor has actually
// been run against.
//
// **Adding a row here is a claim that someone ran the tool against the thing.**
// It is deliberately a hand-maintained list rather than something derived: the
// point is that a person has to state it, and a reviewer can check it against
// docs/validation/.
var realTestedPlatforms = map[string]bool{
	"Apache Kafka":           true,
	"PostgreSQL self-hosted": true,
	"Redpanda self-hosted":   true,
	// Phase 7.5. Both are committed fixtures — test/integration/redis and
	// test/integration/valkey — driven through app.DiagnoseRedis, with ground
	// truth established by redis-cli and valkey-cli before svcdoctor is asked.
	// Neither entry covers Redis Cluster as a cluster or Sentinel as a service:
	// those have their own rows, at Level 0, and this list is per-platform rather
	// than per-protocol precisely so that a cluster-mode *node* passing cannot
	// promote a cluster row.
	"Redis":  true,
	"Valkey": true,
	// Phase 8.2-R3. Both are committed fixtures — test/integration/rabbitmq and
	// test/integration/lavinmq — driven through app.DiagnoseRabbitMQ, with
	// ground truth established by rabbitmqctl and by a scratch AMQP client that
	// shares no code with the implementation, before svcdoctor is asked.
	//
	// Neither entry covers a RabbitMQ **cluster**: svcdoctor opens one
	// connection to one endpoint and discovers nothing, so a single node
	// answering cannot promote a cluster row. That row exists separately, at
	// Level 0. No managed provider was contacted and no cloud credential was
	// used at any point.
	"RabbitMQ": true,
	"LavinMQ":  true,
}

// TestOnlyRealTestedPlatformsClaimLevelTwoOrThree is the central guard.
//
// A platform reaches Level 2 by svcdoctor completing the BASIC journey against a
// real instance, and Level 3 by that plus a repeatable test. Neither is reachable
// by reading documentation, so a row claiming either for an untested platform is
// the exact defect this file exists to catch — one sentence, entirely plausible,
// invisible to every other test.
func TestOnlyRealTestedPlatformsClaimLevelTwoOrThree(t *testing.T) {
	for _, row := range compatibilityRows(t) {
		if !claimsRealEvidence(row) {
			continue
		}
		platform := compatibilityPlatform(row)
		if !realTestedPlatforms[platform] {
			t.Errorf("docs/COMPATIBILITY.md claims Level 2 or 3 for %q, which is not in "+
				"realTestedPlatforms.\n\nLevel 2 means svcdoctor completed the BASIC "+
				"journey against a real instance. If that happened, add the platform to "+
				"realTestedPlatforms in this test and point at the validation document "+
				"that records it. If it did not, the row is a documentation inference "+
				"wearing a test result's clothes.\n\nrow: %s", platform, row)
		}
	}
}

// TestEveryRealTestedPlatformSaysSo is the other direction.
//
// A platform that *was* tested and is recorded at Level 0 or 1 understates, which
// is safer but still wrong, and it usually means a row was edited and the list
// below was not.
func TestEveryRealTestedPlatformSaysSo(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range compatibilityRows(t) {
		platform := compatibilityPlatform(row)
		if realTestedPlatforms[platform] && claimsRealEvidence(row) {
			seen[platform] = true
		}
	}
	for platform := range realTestedPlatforms {
		if !seen[platform] {
			t.Errorf("%q is recorded as really tested but docs/COMPATIBILITY.md gives it "+
				"no Level 2 or 3 row", platform)
		}
	}
}

// unimplementedMechanisms are the authentication mechanisms and connection
// modes svcdoctor does not implement.
//
// Every one of them is standard somewhere, which is exactly why naming one
// beside the word "supported" is so easy to do by accident.
var unimplementedMechanisms = []string{
	"aws_msk_iam", "iam db auth", "iam database authentication",
	"oauthbearer", "gssapi", "kerberos", "scram-sha-512",
	"mtls", "microsoft entra", "auth proxy", "language connectors",
}

// TestNoDocumentClaimsAnUnimplementedMechanism catches the looser phrasing, the
// one a release-note author reaches for.
//
// # Structural, not a phrase list
//
// A first version of this guard listed the exact sentences it expected — "MSK is
// supported", "supports IAM" — and a mutation writing *"IAM DB auth is
// supported"* walked straight past it. Enumerating the ways to say something is
// a losing game. The rule is instead: **any claim unit naming a mechanism
// svcdoctor does not implement must be recording its absence.**
//
// # The unit is a table cell or a sentence, and the distinction matters
//
// Block granularity is too coarse for a table: a compatibility row carries seven
// independent statements, and a denial in the TLS column would exempt a false
// claim in the auth column. Line granularity is too fine for prose, because
// Markdown wraps a sentence across lines and the denial lands on the next one.
// So prose is joined and split into sentences, and a table row is split into
// cells.
func TestNoDocumentClaimsAnUnimplementedMechanism(t *testing.T) {
	for _, name := range operatorFacingDocuments {
		t.Run(name, func(t *testing.T) {
			for _, unit := range claimUnits(readRepoFile(t, name)) {
				lower := strings.ToLower(unit)
				for _, mechanism := range unimplementedMechanisms {
					if !strings.Contains(lower, mechanism) || recordsAbsence(unit) {
						continue
					}
					t.Errorf("%s names %q in a claim that does not record its absence.\n\n"+
						"svcdoctor does not implement it, so any statement mentioning it "+
						"has to be saying so. If this is a false positive, phrase the "+
						"statement as the denial it is rather than widening the guard."+
						"\n\nunit: %s", name, mechanism, unit)
				}
			}
		})
	}
}

// claimUnits splits a Markdown document into the units a reader takes as one
// claim: one table cell, or one sentence of prose with its wrapping undone.
func claimUnits(document string) []string {
	var out []string
	var prose []string

	flush := func() {
		if len(prose) == 0 {
			return
		}
		out = append(out, claimSentences(strings.Join(prose, " "))...)
		prose = nil
	}

	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "|"):
			flush()
			for _, cell := range strings.Split(strings.Trim(trimmed, "|"), "|") {
				// Sentences within the cell, not the whole cell. A "known gaps"
				// column routinely carries several independent statements, and
				// a denial in one of them must not exempt a claim in the next —
				// which is exactly the mutation that survived the cell-level
				// version of this guard.
				out = append(out, claimSentences(strings.TrimSpace(cell))...)
			}
		case strings.HasPrefix(trimmed, "- "), strings.HasPrefix(trimmed, "#"):
			// A new list item or heading ends the previous unit; a continuation
			// line does not, which is what undoes Markdown's wrapping.
			flush()
			prose = append(prose, trimmed)
		default:
			prose = append(prose, trimmed)
		}
	}
	flush()
	return out
}

// recordsAbsence reports whether a claim unit is saying a thing is not there.
//
// It is denies() plus the three markers a compatibility table uses instead of a
// sentence: the ✗ glyph, the UNSUPPORTED evidence label, and "declined", which
// is the word the PostgreSQL mechanism table has always used for a mechanism
// svcdoctor observes and refuses to perform.
func recordsAbsence(unit string) bool {
	lower := strings.ToLower(unit)
	return denies(unit) ||
		strings.Contains(unit, "✗") ||
		strings.Contains(lower, "unsupported") ||
		strings.Contains(lower, "declined")
}

// TestTheCompatibilityGuardCanFail proves the parsing above is not vacuous.
func TestTheCompatibilityGuardCanFail(t *testing.T) {
	rows := compatibilityRows(t)
	if len(rows) < 8 {
		t.Fatalf("found %d compatibility rows; the table parser is not seeing the "+
			"document and every assertion above is vacuous", len(rows))
	}

	planted := "| **AWS MSK — IAM** | Kafka | `SASL_SSL` | yes | YES | **2 — TESTED BASIC** | none |"
	if !claimsRealEvidence(planted) {
		t.Fatal("a planted Level 2 row is not recognized as claiming real evidence")
	}
	if claimsRealEvidence("| **AWS MSK — IAM** | Kafka | x | x | NO | **1 — PROTOCOL-PLAUSIBLE** | x |") {
		t.Error("a Level 1 row is misread as claiming real evidence")
	}
	if got := compatibilityPlatform(planted); got != "AWS MSK — IAM" {
		t.Errorf("platform name = %q, want %q", got, "AWS MSK — IAM")
	}
	if realTestedPlatforms[compatibilityPlatform(planted)] {
		t.Error("a planted MSK IAM row would be accepted as really tested")
	}
}

// claimsRealEvidence reports whether a row claims a level that only a real run
// can produce.
//
// The level names are matched rather than the numbers, because the number is the
// part most likely to be reworded and the name is the part that carries the
// claim. Level 1 is "PROTOCOL-PLAUSIBLE" and level 0 "NOT EVALUATED"; neither
// contains either phrase below.
func claimsRealEvidence(row string) bool {
	return strings.Contains(row, "TESTED BASIC") || strings.Contains(row, "SUPPORTED BASIC")
}

// compatibilityRows returns the platform rows of the compatibility document.
//
// The level-definition table at the top uses the same shape, so a row whose
// first cell begins with a digit is skipped: those define the vocabulary rather
// than making a claim with it.
func compatibilityRows(t *testing.T) []string {
	t.Helper()

	var out []string
	for _, line := range strings.Split(readRepoFile(t, "docs/COMPATIBILITY.md"), "\n") {
		line = strings.TrimSpace(line)
		// A data row, not a header and not the alignment separator.
		if !strings.HasPrefix(line, "| **") || strings.Count(line, "|") < 4 {
			continue
		}
		if name := compatibilityPlatform(line); name == "" ||
			(name[0] >= '0' && name[0] <= '9') {
			continue
		}
		out = append(out, line)
	}
	return out
}

// compatibilityPlatform reads the first cell of a table row, stripped of
// Markdown emphasis and of the version suffix a row may carry.
func compatibilityPlatform(row string) string {
	cells := strings.Split(strings.Trim(row, "|"), "|")
	if len(cells) == 0 {
		return ""
	}
	name := strings.TrimSpace(cells[0])
	if bold := strings.Index(name, "**"); bold == 0 {
		if end := strings.Index(name[2:], "**"); end >= 0 {
			name = name[2 : 2+end]
		}
	}
	return strings.TrimSpace(name)
}

// operatorFacingDocuments are the documents that make claims to an operator who
// has not read the code.
//
// The release notes are in the list because they are the single most
// overclaim-prone document a project produces: written last, written quickly,
// and read by everyone who never reads anything else.
var operatorFacingDocuments = []string{
	"README.md",
	"docs/COMPATIBILITY.md",
	"docs/validation/RELEASE_NOTES_v0.2.0_DRAFT.md",
	// The live release notes, which the comment above has always claimed were
	// covered while only a superseded *draft* actually was. They are also no
	// longer only a document: `release-oci.yml` publishes this file as the
	// GitHub Release body, so an overclaim here is served to every reader of the
	// Releases page rather than to whoever opens the repository.
	releaseNotes,
}

// unqualifiedClaimDocuments are the documents that make claims in running prose,
// where naming a provider *is* the claim.
//
// Deliberately narrower than operatorFacingDocuments, and the exclusions are
// reasons rather than exemptions. `docs/COMPATIBILITY.md` exists precisely to
// name providers, each against a graded level, and that grading is the denial —
// it is held instead by TestOnlyRealTestedPlatformsClaimLevelTwoOrThree and
// TestEveryRealTestedPlatformSaysSo, which are stricter than a prose rule could
// be. The v0.2.0 draft is a superseded artifact that lists providers under a
// heading denying all of them.
//
// The mechanism and health rules stay on the wider list: those are shape-
// agnostic, because naming SCRAM-SHA-512 is an overclaim in a table cell just as
// much as in a sentence.
var unqualifiedClaimDocuments = []string{
	"README.md",
	releaseNotes,
}

// healthClaims are the things svcdoctor observes nothing about.
//
// Each is a claim BASIC structurally cannot make: no exchange in either adapter
// obtains topic, partition, consumer-group, replication or pool state, so a
// document asserting one is describing a different product. ADR 0052 fixed the
// terminal vocabulary on exactly this basis; this extends the same rule to the
// prose an operator reads before ever running the tool.
var healthClaims = []string{
	"cluster health", "cluster is healthy", "broker health", "partition health",
	"consumer lag", "consumer group health", "topic health",
	"replication health", "connection pool health", "query latency",
}

// TestNoDocumentClaimsHealthTheProductCannotObserve guards the release notes and
// their neighbours against the claim BASIC exists to avoid making.
func TestNoDocumentClaimsHealthTheProductCannotObserve(t *testing.T) {
	for _, name := range operatorFacingDocuments {
		t.Run(name, func(t *testing.T) {
			for _, unit := range claimUnits(readRepoFile(t, name)) {
				lower := strings.ToLower(unit)
				for _, claim := range healthClaims {
					if !strings.Contains(lower, claim) || recordsAbsence(unit) {
						continue
					}
					t.Errorf("%s claims %q in a unit that does not deny it.\n\n"+
						"BASIC obtains no topic, partition, consumer-group, replication "+
						"or pool state from either service, so this describes a product "+
						"that does not exist (ADR 0052).\n\nunit: %s", name, claim, unit)
				}
			}
		})
	}
}

// TestTheHealthClaimGuardCanFail proves the guard above is not vacuous.
func TestTheHealthClaimGuardCanFail(t *testing.T) {
	planted := "svcdoctor reports cluster health and consumer lag for every broker"
	found := false
	for _, claim := range healthClaims {
		if strings.Contains(planted, claim) {
			found = true
		}
	}
	if !found {
		t.Error("a planted health claim matches nothing in healthClaims")
	}
	if recordsAbsence(planted) {
		t.Error("a planted health claim reads as a denial")
	}
}

// --- the Redpanda claim, which is true and easy to widen --------------------

// redpandaSupportWords mark a sentence as asserting compatibility rather than
// merely naming the software.
//
// A `make` target line and an operational note about running suites one at a
// time both name Redpanda and claim nothing, so the trigger is the claim, not
// the name.
var redpandaSupportWords = []string{
	"supported", "support for", "tested", "validated", "works", "compatible",
	"compatibility", "certified", "verified against",
}

// redpandaOverclaims are the three widenings ADR 0061's evidence does not cover.
//
// Each is checked against a sentence stripped of Markdown, so a disclaimer
// elsewhere in the paragraph cannot excuse it — but a denial *in the same
// sentence* legitimately can, which is why denies() still applies.
var redpandaOverclaims = []struct{ phrase, why string }{
	{"redpanda cloud", "self-hosted evidence does not transfer to Redpanda Cloud; " +
		"nothing has ever run against it"},
	{"all redpanda", "the fixture pins one version, and Redpanda's SCRAM salt size " +
		"is a compile-time constant in its source"},
	{"any redpanda version", "same reason: one version was measured"},
	{"every redpanda version", "same reason: one version was measured"},
	{"scram-sha-512", "svcdoctor does not implement it, against Redpanda or anything else"},
}

// TestTheREADMEsRedpandaClaimStaysNarrow replaces the blanket ban that
// TestTheREADMENeverClaimsManagedCompatibility used to apply to this name.
//
// Two rules, both structural:
//
//  1. a sentence that *claims* Redpanda compatibility must name the tested
//     version, so the claim cannot silently generalize;
//  2. the named widenings are refused outright.
func TestTheREADMEsRedpandaClaimStaysNarrow(t *testing.T) {
	const testedVersion = "v25.1.9"

	// claimUnits rather than a per-line split: the README wraps prose to a
	// column, so "says nothing about Redpanda Cloud" lands on two lines and a
	// line-wise guard sees the claim without its denial. That is the same defect
	// the compatibility guard already learned.
	for _, doc := range unqualifiedClaimDocuments {
		assertRedpandaClaimStaysNarrow(t, doc, testedVersion)
	}
}

func assertRedpandaClaimStaysNarrow(t *testing.T, name, testedVersion string) {
	t.Helper()

	for _, sentence := range claimUnits(docOutsideRoadmap(t, name)) {
		lower := strings.ToLower(sentence)
		if !strings.Contains(lower, "redpanda") {
			continue
		}

		for _, over := range redpandaOverclaims {
			if strings.Contains(lower, over.phrase) && !denies(sentence) {
				t.Errorf("%s claims %q: %s\n\n  %s", name, over.phrase, over.why, sentence)
			}
		}

		claimsSupport := false
		for _, w := range redpandaSupportWords {
			if strings.Contains(lower, w) {
				claimsSupport = true
				break
			}
		}
		if !claimsSupport || denies(sentence) {
			continue
		}
		if !strings.Contains(sentence, testedVersion) {
			t.Errorf("the README claims Redpanda compatibility without naming the "+
				"tested version %s:\n  %s\n\n"+
				"Redpanda's SCRAM salt size is a compile-time constant in its source, so "+
				"the fixture is evidence about one version. An unversioned claim "+
				"generalizes past what was measured.", testedVersion, sentence)
		}
	}
}

// TestTheRedpandaClaimGuardCanFail proves neither rule above is vacuous.
func TestTheRedpandaClaimGuardCanFail(t *testing.T) {
	// The sentence the README actually carries must satisfy the guard.
	real := "**Redpanda self-hosted v25.1.9 is tested**, `PLAIN` and `SCRAM-SHA-256`, " +
		"by a committed fixture with its own `make` target"
	if !strings.Contains(real, "v25.1.9") {
		t.Fatal("the fixture sentence lost its version")
	}

	// And these must not.
	for _, planted := range []string{
		"Redpanda is supported",
		"svcdoctor is compatible with Redpanda",
		"Redpanda Cloud is supported",
		"all Redpanda versions are tested",
	} {
		lower := strings.ToLower(planted)
		flagged := strings.Contains(lower, "v25.1.9")
		for _, over := range redpandaOverclaims {
			if strings.Contains(lower, over.phrase) {
				flagged = true
			}
		}
		claims := false
		for _, w := range redpandaSupportWords {
			if strings.Contains(lower, w) {
				claims = true
			}
		}
		if !claims && !flagged {
			t.Errorf("a planted claim would slip past both rules: %q", planted)
		}
		if denies(planted) {
			t.Errorf("a planted claim reads as a denial: %q", planted)
		}
	}
}

// readmeOutsideRoadmap returns the README with its Roadmap section removed.
//
// The Roadmap is exempt for the reason it is exempt from the managed-provider
// guard: its entire content is work not yet done, so naming a platform there
// claims nothing. "Redpanda Cloud" appears in it as an open item and must keep
// being allowed to.
// docOutsideRoadmap is the same exclusion for any operator-facing document. The
// Roadmap exemption is harmless where there is no Roadmap section, which is what
// lets one rule cover the README and the release notes without either needing a
// copy of it.
func docOutsideRoadmap(t *testing.T, name string) string {
	t.Helper()

	var kept []string
	inRoadmap := false
	for _, line := range strings.Split(readRepoFile(t, name), "\n") {
		if strings.HasPrefix(line, "## ") {
			inRoadmap = strings.Contains(line, "Roadmap")
		}
		if !inRoadmap {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
