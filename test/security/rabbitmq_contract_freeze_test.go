package security_test

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// RabbitMQ contract-freeze guard.
//
// # Why a negative guard exists at all
//
// Phase 8.1 froze the RabbitMQ BASIC contract in ADRs 0067 to 0070 and wrote no
// RabbitMQ code. That is ADR 0054's ordering — an owner before a producer — and
// it has a failure mode this file exists to catch: a contract nobody reads.
//
// The precedent is `kafka_production_reachability_test.go`, which until Phase
// 6.1c asserted that `internal/adapter/kafka` had zero production importers and
// that no `DiagnoseKafka` existed. That negative stopped the first attempt at
// Kafka composition, which would have let a rejected credential arrive as
// `findings: []`, `status: OK`, exit 0. This file is the same shape for
// RabbitMQ, and it is expected to be **turned around rather than deleted** when
// the implementation phase lands: where it now says *nothing exists*, it will
// say *exactly this exists and exactly these rules explain it*.
//
// # What it can and cannot prove
//
// These are static guards over the tree and over the documents. They prove that
// the frozen decisions have not been quietly pre-empted, and that the compat
// document has not started claiming a protocol the binary cannot speak. They
// prove nothing about behaviour, because there is no behaviour yet.

// The RabbitMQ production closure, in its final form.
//
// # This file has been turned around twice, and never deleted
//
// Phase 8.1 asserted that no RabbitMQ package existed at all — the contract
// freeze in executable form. Phase 8.2 turned it to "the producer exists and
// nothing can reach it", which is ADR 0054's window: evidence that can fail does
// not ship before something can explain it. The diagnosis package and the
// composition root then landed together, so the window has closed and the file
// now asserts the positive.
//
// Where it used to say *nothing exists*, it now says **exactly this exists,
// exactly one thing reaches it, exactly these rules explain it, and exactly one
// path may spend a credential.** That is the per-service closure test ADR 0054
// §5 asks for, and it is the same move `kafka_production_reachability_test.go`
// made at the same point in the same rule.
const (
	rabbitmqAdapter          = modulePath + "/internal/adapter/rabbitmq"
	rabbitmqCompositionRoot  = modulePath + "/internal/app"
	rabbitmqCompositionFile  = "internal/app/rabbitmq.go"
	rabbitmqCompositionEntry = "DiagnoseRabbitMQ"
)

// TestExactlyOneProductionPackageReachesTheRabbitMQAdapter is the import guard,
// in its positive form.
//
// The reach is what creates the exposure, so the reach is what this asserts
// about. A renderer, the CLI, a platform collector or a second adapter acquiring
// that import would fail, and so would a second composition root.
func TestExactlyOneProductionPackageReachesTheRabbitMQAdapter(t *testing.T) {
	root := repositoryRoot(t)

	var importers []string
	for _, dir := range productionPackages(t, root) {
		path := importPath(t, root, dir)
		// The adapter and its own wire package are what this governs, not what
		// it constrains.
		if strings.HasPrefix(path, rabbitmqAdapter) {
			continue
		}
		pkg, err := gobuild.ImportDir(dir, gobuild.ImportComment)
		if err != nil {
			continue
		}
		if slices.Contains(pkg.Imports, rabbitmqAdapter) {
			importers = append(importers, path)
		}
	}

	if !slices.Equal(importers, []string{rabbitmqCompositionRoot}) {
		t.Errorf("production importers of %s = %v, want exactly [%s].\n\n"+
			"Every RabbitMQ outcome is reachable from whatever imports the adapter. "+
			"One composition root is reviewable; a second one, or an import from the "+
			"CLI or a renderer, is a second place credentials and sockets are "+
			"sequenced. See ADR 0054.",
			rabbitmqAdapter, importers, rabbitmqCompositionRoot)
	}
}

// TestExactlyOneRabbitMQCompositionEntryPointExists replaces the old
// "no DiagnoseRabbitMQ exists" assertion with "exactly one does, and it is here".
//
// A second entry point means two credential-authority decisions, two path
// selections, and two chances for one of them to be the unreviewed one.
func TestExactlyOneRabbitMQCompositionEntryPointExists(t *testing.T) {
	root := repositoryRoot(t)

	var declared []string
	for _, dir := range productionPackages(t, root) {
		pkg, err := gobuild.ImportDir(dir, 0)
		if err != nil {
			continue
		}
		for _, name := range pkg.GoFiles {
			path := filepath.Join(dir, name)
			for _, fn := range functionsIn(t, path) {
				if fn.Name.Name == rabbitmqCompositionEntry {
					relative, relErr := filepath.Rel(root, path)
					if relErr != nil {
						t.Fatalf("relating %s: %v", path, relErr)
					}
					declared = append(declared, filepath.ToSlash(relative))
				}
			}
		}
	}

	if !slices.Equal(declared, []string{rabbitmqCompositionFile}) {
		t.Errorf("%s is declared in %v, want exactly [%s]",
			rabbitmqCompositionEntry, declared, rabbitmqCompositionFile)
	}
}

// TestTheRabbitMQCompositionWiresEveryOwnerOfWhatItCanProduce is the ADR 0054
// closure assertion in its positive form.
//
// DiagnoseRabbitMQ makes four families of evidence production-reachable: generic
// DNS, generic TCP, generic requested-target TLS, and the three RabbitMQ protocol
// steps. Every one has an owner, and this asserts the composition actually
// **wires** all of them — an owner that exists and is not wired is
// indistinguishable, in the report, from an owner that does not exist.
//
// The list is exact in both directions. A rule listed here that the composition
// does not wire is a silence; a rule wired that is not listed is an unreviewed
// claim reaching a report.
func TestTheRabbitMQCompositionWiresEveryOwnerOfWhatItCanProduce(t *testing.T) {
	want := []string{
		// The generic failure boundary, activated in Phase 10.1b (ADR 0079).
		"diagnosis.FailureBoundary",
		"diagnosistransport.DNS",
		"diagnosistransport.TCP",
		"diagnosistransport.TLS",
		"diagnosisrabbitmq.ConnectionStart",
		"diagnosisrabbitmq.Authentication",
		"diagnosisrabbitmq.ConnectionOpen",
	}

	wantIDs := []string{
		"diag/failure-boundary",
		"transport/dns",
		"transport/tcp",
		"transport/tls",
		"rabbitmq/connection-start",
		"rabbitmq/authentication",
		"rabbitmq/connection-open",
	}

	gotIDs, got := rulesWiredIn(t, filepath.Join(repositoryRoot(t), rabbitmqCompositionFile))
	if !slices.Equal(got, want) {
		t.Errorf("DiagnoseRabbitMQ wires %v, want exactly %v.\n\n"+
			"An outcome the adapter can produce with no rule to explain it reaches "+
			"the report as silence (ADR 0054).", got, want)
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Errorf("DiagnoseRabbitMQ registers %v, want exactly %v (ADR 0080 section 2.5).",
			gotIDs, wantIDs)
	}
}

// TestTheRabbitMQCompositionHasNoRetryOrRediscoveryPath is the behavioural half
// asserted structurally.
//
// One connection past the credential boundary, no redial, no reconnect, no
// second authentication, and no discovery of another endpoint. None of these is
// forbidden by a runtime check that could be reset — they are unwritten, and
// this asserts they stay unwritten.
func TestTheRabbitMQCompositionHasNoRetryOrRediscoveryPath(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), rabbitmqCompositionFile)

	// **Identifiers, not source text.** A first version of this scanned the raw
	// file and failed on the doc comments that *promise* there is no reconnect —
	// a guard that forbids describing the invariant it enforces is worse than no
	// guard, because the fix is to delete the explanation.
	var named []string
	ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			named = append(named, node.Name)
		case *ast.SelectorExpr:
			named = append(named, node.Sel.Name)
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				named = append(named, node.Value)
			}
		}
		return true
	})

	forbidden := []string{
		"Retry", "Reconnect", "Redial", "Fallback", "Discover",
		"Channel", "Queue", "Exchange", "Management", "Cluster",
	}

	// **One legitimate collision, named rather than excused.**
	//
	// "Exchange" has two senses here. `ExchangeTimeout` bounds one request and
	// response — the round-trip sense every adapter in this repository uses —
	// and has nothing to do with an AMQP Exchange, which is the customer
	// topology object BASIC never names. Allowlisting the exact identifier keeps
	// the broad word check, so `ExchangeDeclare` still fails.
	allowed := map[string]bool{"ExchangeTimeout": true}

	for _, name := range named {
		if allowed[name] {
			continue
		}
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("%s references %q (in identifier %q).\n\n"+
					"RabbitMQ BASIC opens one connection, spends one credential on it, "+
					"and stops at Connection.Open-Ok. None of retry, reconnect, "+
					"discovery, channels, queues, exchanges, the management API or "+
					"cluster traversal is part of it (ADR 0067 §6, ADR 0068 §5).",
					rabbitmqCompositionFile, bad, name)
			}
		}
	}

	// Exactly one call to the credential-bearing adapter entry point.
	calls := 0
	ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Authenticate" {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "rabbitmq" {
				calls++
			}
		}
		return true
	})
	if calls != 1 {
		t.Errorf("%s calls rabbitmq.Authenticate %d times, want exactly 1.\n\n"+
			"One credential-bearing attempt per run is by construction rather than by "+
			"a counter, and this is what makes that true (ADR 0068 §5).",
			rabbitmqCompositionFile, calls)
	}
}

// TestTheRabbitMQClosureGuardCanFail proves the predicates above are live.
func TestTheRabbitMQClosureGuardCanFail(t *testing.T) {
	planted := "\t\t_ = rabbitmq.OpenChannel(ctx) // reconnect on failure\n"
	hits := 0
	for _, forbidden := range []string{"reconnect", "Channel"} {
		if strings.Contains(planted, forbidden) {
			hits++
		}
	}
	if hits != 2 {
		t.Errorf("the forbidden-surface predicate matched %d of 2 planted surfaces", hits)
	}
	if !slices.Equal([]string{"a"}, []string{"a"}) {
		t.Error("the rule-set comparison is not live")
	}

	// The one allowlisted identifier must not become a hole: a name that merely
	// starts with it still fails.
	for _, planted := range []string{"ExchangeDeclare", "QueueDeclare", "ChannelOpen"} {
		matched := false
		for _, bad := range []string{"Channel", "Queue", "Exchange"} {
			if strings.Contains(planted, bad) && planted != "ExchangeTimeout" {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%q would pass the forbidden-surface check", planted)
		}
	}
}

// TestTheRabbitMQContractRecordsExist proves the freeze is written down.
//
// The negative above is only safe while the positive it defers to is readable.
// A deleted or renamed record would leave a guard forbidding work with no
// document explaining what to build instead.
func TestTheRabbitMQContractRecordsExist(t *testing.T) {
	records := map[string]string{
		"docs/decisions/0067-rabbitmq-basic-journey-and-terminal-boundary.md":         "Connection.Open-Ok",
		"docs/decisions/0068-rabbitmq-authentication-and-credential-authority.md":     "authentication_failure_close",
		"docs/decisions/0069-rabbitmq-vhost-authorization-and-close-normalization.md": "UNSPECIFIED_TRUNCATED",
		"docs/decisions/0070-rabbitmq-tune-contract-and-wire-bounds.md":               "channel_max",
	}
	root := repositoryRoot(t)
	for name, mustMention := range records {
		source, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // a repository path this test built.
		if err != nil {
			t.Errorf("%s is missing: the freeze guard forbids work that this record "+
				"is supposed to describe: %v", name, err)
			continue
		}
		text := string(source)
		if !strings.Contains(text, "Accepted in Phase 8.1") {
			t.Errorf("%s no longer records itself as accepted in Phase 8.1", name)
		}
		if !strings.Contains(text, mustMention) {
			t.Errorf("%s no longer mentions %q, which is one of the things it exists "+
				"to freeze", name, mustMention)
		}
	}
}

// TestTheCompatibilityDocumentDeniesRabbitMQ is the truthfulness half.
//
// svcdoctor cannot speak AMQP 0-9-1. A compatibility row that stopped saying so
// would be the exact defect `internal/cli/docsclaims_test.go` exists to catch,
// for a protocol that guard does not know about yet.
func TestTheCompatibilityDocumentGradesRabbitMQTruthfully(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "docs/COMPATIBILITY.md")) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("read docs/COMPATIBILITY.md: %v", err)
	}
	text := string(source)

	// Turned around at Phase 8.2-R3, and not deleted. Where this used to assert
	// that no AMQP row could claim evidence, it now asserts that exactly the
	// versions a committed fixture exercises may claim it — and that nothing
	// else may.
	if strings.Contains(text, "RabbitMQ and LavinMQ — decided, and NOT IMPLEMENTED") {
		t.Error("docs/COMPATIBILITY.md still says RabbitMQ is not implemented, but " +
			"internal/adapter/rabbitmq exists and a committed fixture exercises it")
	}

	// The exact versions the fixtures pin. A row claiming a tested level for
	// anything else is a claim nobody ran.
	validated := []string{"4.2.0", "4.0.9", "3.13.7", "2.3.0"}

	// Managed providers stay at Level 0. Compatibility is never inferred from
	// protocol similarity, and no cloud credential was used at any point.
	managed := []string{
		"amazon mq", "cloudamqp", "azure", "gcp", "managed amqp",
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "rabbitmq") && !strings.Contains(lower, "lavinmq") &&
			!strings.Contains(lower, "amqp") {
			continue
		}

		claimsEvidence := strings.Contains(line, "TESTED BASIC") ||
			strings.Contains(line, "SUPPORTED BASIC")
		if !claimsEvidence {
			continue
		}

		for _, name := range managed {
			if strings.Contains(lower, name) {
				t.Errorf("a managed provider claims real evidence while no cloud "+
					"credential was ever used.\n\nrow: %s", line)
			}
		}

		named := false
		for _, v := range validated {
			if strings.Contains(line, v) {
				named = true
			}
		}
		if !named {
			t.Errorf("a row claims a tested level without naming a version the "+
				"fixtures actually exercise %v.\n\nrow: %s", validated, line)
		}
	}

	// Clusters and client certificates were not validated and must not be
	// claimed.
	//
	// **A denial is not a claim.** The document says "not that a cluster is
	// healthy" precisely to rule the inference out, so a naive substring search
	// would fail on the sentence that exists to prevent the thing being
	// searched for. Only an un-negated occurrence counts.
	for _, forbidden := range []string{
		"cluster is healthy", "mTLS supported", "client certificate ✓",
	} {
		if claimedAffirmatively(text, forbidden) {
			t.Errorf("docs/COMPATIBILITY.md claims %q, which nothing validated", forbidden)
		}
	}
}

// claimedAffirmatively reports whether phrase appears outside a negation.
//
// It looks back a short window for a negating word. That is deliberately
// simple: the alternative is parsing English, and the only thing this needs to
// separate is "X is healthy" from "not that X is healthy".
func claimedAffirmatively(text, phrase string) bool {
	const window = 24
	for i := 0; ; {
		j := strings.Index(text[i:], phrase)
		if j < 0 {
			return false
		}
		at := i + j
		lo := at - window
		if lo < 0 {
			lo = 0
		}
		before := strings.ToLower(text[lo:at])
		negated := strings.Contains(before, "not ") || strings.Contains(before, "never ") ||
			strings.Contains(before, "no ")
		if !negated {
			return true
		}
		i = at + len(phrase)
	}
}

// TestTheRabbitMQCompatibilityGuardCanFail proves the grading guard is not
// vacuous, by running its own rules against rows that break them.
func TestTheRabbitMQCompatibilityGuardCanFail(t *testing.T) {
	validated := []string{"4.2.0", "4.0.9", "3.13.7", "2.3.0"}
	managed := []string{"amazon mq", "cloudamqp", "azure", "gcp"}

	cases := []struct {
		name string
		row  string
		want bool // true when the rules should reject the row
	}{
		{"managed provider claiming evidence",
			"| **Amazon MQ for RabbitMQ** | AMQP 0-9-1 | yes | **3 — SUPPORTED BASIC** |", true},
		{"an unvalidated version claiming evidence",
			"| **RabbitMQ** 3.9.0 | AMQP 0-9-1 | yes | **2 — TESTED BASIC** |", true},
		{"a validated version claiming evidence",
			"| **RabbitMQ** 4.2.0 | AMQP 0-9-1 | yes | **3 — SUPPORTED BASIC** |", false},
		{"an unvalidated version claiming nothing",
			"| **RabbitMQ** 3.9.0 | AMQP 0-9-1 | no | **0 — NOT EVALUATED** |", false},
	}

	// The negation rule has to be shown to work in both directions too.
	if claimedAffirmatively("not that a cluster is healthy", "cluster is healthy") {
		t.Error("a denial was read as a claim")
	}
	if !claimedAffirmatively("the cluster is healthy", "cluster is healthy") {
		t.Error("an affirmative claim was not detected")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lower := strings.ToLower(tc.row)
			claims := strings.Contains(tc.row, "TESTED BASIC") ||
				strings.Contains(tc.row, "SUPPORTED BASIC")

			rejected := false
			if claims {
				for _, name := range managed {
					if strings.Contains(lower, name) {
						rejected = true
					}
				}
				named := false
				for _, v := range validated {
					if strings.Contains(tc.row, v) {
						named = true
					}
				}
				if !named {
					rejected = true
				}
			}
			if rejected != tc.want {
				t.Errorf("rules rejected = %v, want %v; the grading guard cannot "+
					"distinguish a truthful row from an invented one", rejected, tc.want)
			}
		})
	}
}

// --- the one thing Phase 8.1 did implement ----------------------------------

// TestResourceLimitReachedIsNamedAndDistinct pins the single production change.
//
// The class was added for a condition **two** services produce, which is the bar
// `internal/adapter/postgres/establish.go` had written down while declining to
// create one. Naming it here as well as in the domain package is deliberate: the
// domain test proves the vocabulary is coherent, and this one proves the class
// survives as a cross-service fact rather than a PostgreSQL detail.
func TestResourceLimitReachedIsNamedAndDistinct(t *testing.T) {
	if got := domain.FailureResourceLimitReached.String(); got != "RESOURCE_LIMIT_REACHED" {
		t.Errorf("class name = %q, want RESOURCE_LIMIT_REACHED", got)
	}
	for _, other := range []domain.FailureClass{
		domain.FailureAuthzDenied,
		domain.FailureAuthzNotPermitted,
		domain.FailureResourceNotFound,
		domain.FailureProtocolUnexpectedResponse,
	} {
		if domain.FailureResourceLimitReached == other {
			t.Errorf("a named capacity ceiling collapsed into %s", other)
		}
	}
}

// TestPostgresConnectionLimitUsesTheSharedClass proves the migration landed.
//
// Two services classifying the identical condition differently would be worse
// than either choice alone, which is why ADR 0069 section 6.1 made the migration
// part of the decision rather than a follow-up. This asserts it through the
// package's exported surface, so it fails if the mapping is reverted.
func TestPostgresConnectionLimitUsesTheSharedClass(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "internal/adapter/postgres/establish.go")) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("read establish.go: %v", err)
	}
	text := string(source)
	if !strings.Contains(text, `case "53300":`) ||
		!strings.Contains(text, "domain.FailureResourceLimitReached") {
		t.Error("PostgreSQL SQLSTATE 53300 no longer maps to RESOURCE_LIMIT_REACHED.\n\n" +
			"ADR 0069 section 6.1 makes this pairing part of the decision: reverting it " +
			"leaves two services classifying one condition differently.")
	}

	// And the package still exists to be classified against, which keeps this
	// guard from passing vacuously if the file is moved.
	if postgres.StepSession == "" {
		t.Error("internal/adapter/postgres no longer exposes StepSession")
	}
}

// --- the authorized finding table -------------------------------------------

// TestTheAuthorizedRabbitMQTableIsExactlyTheProducedCodes is the ADR 0054
// closure test for RabbitMQ, and it reads the frozen contract rather than
// repeating it.
//
// It parses the finding table out of ADR 0069 §7 and compares it against the
// constants `internal/diagnosis/rabbitmq` declares, failing in **both**
// directions: an authorized code with no declaration is a silence, and a
// declared code the ADR does not authorize is an unreviewed claim reaching a
// report.
//
// # Why it lives here rather than beside the rules
//
// `internal/diagnosis/*` is denied the `os` import by depguard — diagnosis must
// not read files, the environment or process state — and that boundary is right.
// A guard that reads an ADR is a structural test, and structural tests live in
// this package beside the Kafka closure guard.
//
// # Why it derives rather than repeats
//
// Phase 8.2-R1 struck `RABBITMQ_PEER_VERIFICATION_FAILED` from the ADR. Had this
// held a hand-written list, the strike would have needed a second edit somebody
// could forget, and the enforced count would have drifted from the contract it
// is supposed to enforce.
func TestTheAuthorizedRabbitMQTableIsExactlyTheProducedCodes(t *testing.T) {
	authorized := authorizedRabbitMQCodes(t)
	declared := declaredRabbitMQCodes(t)

	if len(authorized) == 0 {
		t.Fatal("no codes were parsed out of ADR 0069 section 7; this guard would pass vacuously")
	}
	if len(declared) == 0 {
		t.Fatal("no codes were parsed out of internal/diagnosis/rabbitmq; this guard would " +
			"pass vacuously")
	}

	for code := range authorized {
		if !declared[code] {
			t.Errorf("ADR 0069 authorizes %s and internal/diagnosis/rabbitmq declares no "+
				"such code.\n\nAn authorized outcome with no producer is a silence: the "+
				"condition occurs and the report says nothing.", code)
		}
	}
	for code := range declared {
		if !authorized[code] {
			t.Errorf("internal/diagnosis/rabbitmq declares %s and ADR 0069 does not "+
				"authorize it.\n\nA finding nobody reviewed is reaching a report. Amend "+
				"the ADR deliberately or remove the code.", code)
		}
	}
}

// TestNoRabbitMQPeerVerificationFindingExists is the Phase 8.2-R1 regression
// guard.
//
// `AUTH_PEER_VERIFICATION_FAILED` means the *peer* failed to prove its own
// knowledge of the authentication material, in a mechanism where both parties
// authenticate. Its only producers in this repository are inside SCRAM paths.
//
// **SASL PLAIN is not mutual.** The broker returns no reciprocal proof, so there
// is nothing to verify and nothing that can fail. A RabbitMQ peer-verification
// finding would be permanently unreachable — declared, present in no report, and
// quietly implying svcdoctor checks something it does not.
//
// The mistake is easy to make twice: the two neighbouring services both have
// such a code, and copying their finding table is the obvious way to start.
func TestNoRabbitMQPeerVerificationFindingExists(t *testing.T) {
	for code := range declaredRabbitMQCodes(t) {
		if strings.Contains(string(code), "PEER_VERIFICATION") {
			t.Errorf("%s is declared.\n\n"+
				"RabbitMQ BASIC authenticates with SASL PLAIN, which is not a mutual "+
				"mechanism: the broker returns no proof, so no peer verification can "+
				"fail. TLS trust and identity failures belong to the generic TLS_* "+
				"findings at the tls.handshake node (ADR 0053), exactly as they do for "+
				"Redis. See ADR 0069 section 7.1.", code)
		}
	}
}

// TestNoRabbitMQProducerMapsToPeerVerification is the other half, one layer down.
//
// The finding code is the visible surface; the failure class is what a producer
// would have to emit. Naming the class without declaring a code would put an
// unreachable-by-design class on a RabbitMQ node.
func TestNoRabbitMQProducerMapsToPeerVerification(t *testing.T) {
	for _, path := range rabbitmqProductionFiles(t) {
		source, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(source), "FailureAuthPeerVerificationFailed") {
			rel, _ := filepath.Rel(repositoryRoot(t), path)
			t.Errorf("%s names FailureAuthPeerVerificationFailed.\n\n"+
				"No RabbitMQ BASIC execution can reach it: PLAIN is not a mutual "+
				"mechanism. See ADR 0069 section 7.1.", filepath.ToSlash(rel))
		}
	}
}

// TestTheRabbitMQPeerVerificationGuardsCanFail proves both are live.
func TestTheRabbitMQPeerVerificationGuardsCanFail(t *testing.T) {
	planted := []string{"RABBITMQ_PEER_VERIFICATION_FAILED", "RABBITMQ_CREDENTIALS_REJECTED"}
	hits := 0
	for _, code := range planted {
		if strings.Contains(code, "PEER_VERIFICATION") {
			hits++
		}
	}
	if hits != 1 {
		t.Errorf("the code predicate matched %d of the planted codes, want 1", hits)
	}
	if !strings.Contains("\treturn domain.FailureAuthPeerVerificationFailed\n",
		"FailureAuthPeerVerificationFailed") {
		t.Error("the class predicate does not match a planted mapping")
	}
}

// authorizedRabbitMQCodes parses the finding table out of ADR 0069 §7.
func authorizedRabbitMQCodes(t *testing.T) map[domain.FindingCode]bool {
	t.Helper()

	path := filepath.Join(repositoryRoot(t),
		"docs/decisions/0069-rabbitmq-vhost-authorization-and-close-normalization.md")
	source, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("read ADR 0069: %v", err)
	}
	text := string(source)

	start := strings.Index(text, "## 7. Finding vocabulary")
	if start < 0 {
		t.Fatal("ADR 0069 has no section 7; the frozen table cannot be located")
	}
	rest := text[start:]
	end := strings.Index(rest, "### 7.1")
	if end < 0 {
		t.Fatal("ADR 0069 section 7 has no 7.1 terminator")
	}

	// Table rows only: a leading pipe, then a backticked code. Prose elsewhere in
	// the section mentions codes too, and mentioning is not authorizing.
	row := regexp.MustCompile("(?m)^\\| `(RABBITMQ_[A-Z_]+)` \\|")
	out := map[domain.FindingCode]bool{}
	for _, m := range row.FindAllStringSubmatch(rest[:end], -1) {
		out[domain.FindingCode(m[1])] = true
	}
	return out
}

// declaredRabbitMQCodes reads the typed constants the diagnosis package declares.
func declaredRabbitMQCodes(t *testing.T) map[domain.FindingCode]bool {
	t.Helper()

	dir := filepath.Join(repositoryRoot(t), "internal/diagnosis/rabbitmq")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read internal/diagnosis/rabbitmq: %v", err)
	}

	out := map[domain.FindingCode]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		for _, spec := range constSpecsIn(t, filepath.Join(dir, entry.Name())) {
			sel, ok := spec.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "FindingCode" {
				continue
			}
			for i := range spec.Names {
				if i >= len(spec.Values) {
					continue
				}
				lit, ok := spec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					t.Fatalf("unquote: %v", uerr)
				}
				out[domain.FindingCode(v)] = true
			}
		}
	}
	return out
}

// constSpecsIn returns every typed const spec in one file.
func constSpecsIn(t *testing.T, path string) []*ast.ValueSpec {
	t.Helper()

	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []*ast.ValueSpec
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if ok && vs.Type != nil {
				out = append(out, vs)
			}
		}
	}
	return out
}

// rabbitmqProductionFiles lists every non-test Go file in the RabbitMQ packages.
func rabbitmqProductionFiles(t *testing.T) []string {
	t.Helper()

	root := repositoryRoot(t)
	var out []string
	for _, pkg := range []string{
		"internal/adapter/rabbitmq",
		"internal/adapter/rabbitmq/wire",
		"internal/diagnosis/rabbitmq",
		"internal/service/rabbitmq",
	} {
		dir := filepath.Join(root, pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	if len(out) == 0 {
		t.Fatal("no RabbitMQ production files found; these guards would pass vacuously")
	}
	return out
}
