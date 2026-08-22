package redaction

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Identity canaries. They are shaped like the values a service adapter would
// record. Nothing in the production package knows that any such service exists.
const (
	canaryRole     = "payments_writer"
	canaryDatabase = "payments_prod"
)

// identityReport builds a local report whose single node carries the given
// attributes and nothing else identifying, so a surviving value can only have
// come from those attributes.
func identityReport(t *testing.T, attrs map[domain.AttributeKey]domain.AttrValue) domain.Report {
	t.Helper()
	return reportWithHostAttributes(t, attrs)
}

// identityOf reads one identity-kinded attribute back out of the single node.
func identityOf(t *testing.T, report domain.Report, key domain.AttributeKey) string {
	t.Helper()
	nodes := report.Graph().Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	v, ok := nodes[0].Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing", key)
	}
	id, ok := v.Identity()
	if !ok {
		t.Fatalf("attribute %s has kind %s, want identity", key, v.Kind())
	}
	return id
}

// attrTextOf reads any string-shaped attribute back as text, whatever its kind.
func attrTextOf(t *testing.T, report domain.Report, key domain.AttributeKey) string {
	t.Helper()
	nodes := report.Graph().Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	v, ok := nodes[0].Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing", key)
	}
	return v.String()
}

// --- 20.2 basic redaction ----------------------------------------------------

// TestDeclaredIdentityIsPseudonymized is the phase in one test: a producer
// declares two logical identities, and neither raw value survives a shareable
// report while both remain distinguishable and correlatable.
func TestDeclaredIdentityIsPseudonymized(t *testing.T) {
	local := identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role":     domain.IdentityAttr(canaryRole),
		"probe.database": domain.IdentityAttr(canaryDatabase),
	})
	shareable := mustRedact(t, local)

	if got := shareable.Security().OutputMode(); got != domain.OutputModeShareableRedacted {
		t.Fatalf("output mode = %s, want SHAREABLE_REDACTED", got)
	}

	role := identityOf(t, shareable, "probe.role")
	database := identityOf(t, shareable, "probe.database")

	// Sorted assignment: "payments_prod" < "payments_writer".
	if database != "identity-001" {
		t.Errorf("database pseudonym = %q, want identity-001", database)
	}
	if role != "identity-002" {
		t.Errorf("role pseudonym = %q, want identity-002", role)
	}
	if role == database {
		t.Error("two distinct identities received the same pseudonym")
	}

	encoded := encode(t, shareable)
	for _, raw := range []string{canaryRole, canaryDatabase} {
		if strings.Contains(encoded, raw) {
			t.Errorf("raw identity %q survived into the shareable report", raw)
		}
	}
	// The key is untouched: it is what tells a reader which identity is which.
	if !strings.Contains(encoded, `"probe.role"`) || !strings.Contains(encoded, `"probe.database"`) {
		t.Error("an attribute key was rewritten; keys carry the semantic role and must survive")
	}
	if got := shareable.Security().Redactions().Identity; got != 2 {
		t.Errorf("identity redaction count = %d, want 2", got)
	}
}

// TestIdentityKeepsItsKindThroughRedaction stops the transformation from
// quietly downgrading a declared identity to a plain string, which would make a
// second redaction of the same report unable to find it.
func TestIdentityKeepsItsKindThroughRedaction(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role": domain.IdentityAttr(canaryRole),
	}))

	v, _ := shareable.Graph().Nodes()[0].Attribute("probe.role")
	if v.Kind() != domain.AttrKindIdentity {
		t.Errorf("kind after redaction = %s, want identity", v.Kind())
	}
}

// --- 20.3 repeated identity --------------------------------------------------

// TestRepeatedIdentityKeepsOnePseudonym is the correlation half of the
// contract. A reader must still see that the same principal appears in three
// places; they must not learn which principal it is.
func TestRepeatedIdentityKeepsOnePseudonym(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role":      domain.IdentityAttr(canaryRole),
		"probe.owner":     domain.IdentityAttr(canaryRole),
		"probe.requester": domain.IdentityAttr(canaryRole),
	}))

	first := identityOf(t, shareable, "probe.role")
	for _, key := range []domain.AttributeKey{"probe.owner", "probe.requester"} {
		if got := identityOf(t, shareable, key); got != first {
			t.Errorf("%s = %q, want %q: one identity must map to one pseudonym", key, got, first)
		}
	}

	// Counts are of distinct values, matching every other category.
	if got := shareable.Security().Redactions().Identity; got != 1 {
		t.Errorf("identity count = %d, want 1 (distinct values, not occurrences)", got)
	}
}

// --- 20.4 distinct identities, order independence -----------------------------

// TestIdentityPseudonymsDoNotDependOnAssemblyOrder is the determinism proof.
//
// Pseudonyms are assigned from the sorted set of collected values, so the order
// nodes were added to the graph, and the order Go happens to range over an
// attribute map, cannot reach the output.
func TestIdentityPseudonymsDoNotDependOnAssemblyOrder(t *testing.T) {
	keys := []domain.AttributeKey{"probe.ka", "probe.kb", "probe.kc", "probe.kd", "probe.ke"}
	identities := []string{"zulu_role", "alpha_role", "mike_db", "bravo_db", "yankee_tenant"}

	// The same key-to-identity mapping, built by iterating in opposite
	// directions. Go randomizes map iteration anyway, so the second build also
	// exercises a different attribute traversal order on every run.
	forward := map[domain.AttributeKey]domain.AttrValue{}
	reverse := map[domain.AttributeKey]domain.AttrValue{}
	for i := range identities {
		forward[keys[i]] = domain.IdentityAttr(identities[i])
	}
	for i := len(identities) - 1; i >= 0; i-- {
		reverse[keys[i]] = domain.IdentityAttr(identities[i])
	}

	want := encode(t, mustRedact(t, identityReport(t, forward)))
	for i := 0; i < 50; i++ {
		if got := encode(t, mustRedact(t, identityReport(t, reverse))); got != want {
			t.Fatalf("iteration %d produced a different report:\n got %s\nwant %s", i, got, want)
		}
	}
}

// --- 20.5 host and identity sharing raw text ----------------------------------

// TestHostAndIdentityWithTheSameTextStayInSeparateNamespaces pins the collision
// policy.
//
// The declared kind decides the namespace, so the same text is "host-001" where
// a producer said it names a peer and "identity-001" where a producer said it
// names a principal. Neither leaks, and neither is described as the other kind
// of thing.
func TestHostAndIdentityWithTheSameTextStayInSeparateNamespaces(t *testing.T) {
	const shared = "payments"

	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.host": domain.HostAttr(shared),
		"probe.role": domain.IdentityAttr(shared),
	}))

	host := attrTextOf(t, shareable, "probe.host")
	role := identityOf(t, shareable, "probe.role")

	if !strings.HasPrefix(host, "host-") {
		t.Errorf("host attribute = %q, want a host-NNN pseudonym", host)
	}
	if !strings.HasPrefix(role, "identity-") {
		t.Errorf("role attribute = %q, want an identity-NNN pseudonym; "+
			"a declared identity must not be numbered as a machine", role)
	}
	if strings.Contains(encode(t, shareable), shared) {
		t.Errorf("the shared raw text %q survived", shared)
	}

	// Two hostnames: the fixture's vantage host, and the shared text declared as
	// a peer. One identity: the same shared text declared as a principal. One raw
	// value declared under two kinds is two removals in two categories.
	counts := shareable.Security().Redactions()
	if counts.Hostname != 2 || counts.Identity != 1 {
		t.Errorf("counts = hostname %d, identity %d; want 2 and 1",
			counts.Hostname, counts.Identity)
	}
}

// --- 20.6 identity and ordinary string sharing raw text ------------------------

// TestDeclaringAnIdentityMakesTheTokenSensitiveEverywhere pins the propagation
// policy, which is the most consequential decision in this phase.
//
// The contract is **global once declared**, and it is inherited rather than
// invented: an ordinary string attribute whose text equals a collected hostname
// is already rewritten today. Identity joins that rule, so a producer that
// declares a role in one place and repeats it as plain text in another does not
// leak it through the second.
//
// The reverse direction is not implied and is not claimed: a value nobody ever
// declared stays exactly as it arrived. That is the limitation ADR 0037 §3
// records, and TestUndeclaredIdentityIsNotRecognized pins it honestly.
func TestDeclaringAnIdentityMakesTheTokenSensitiveEverywhere(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role":  domain.IdentityAttr(canaryRole),
		"probe.notes": domain.StringAttr(canaryRole),
		"probe.list":  domain.StringListAttr(canaryRole, "TLSv1.3"),
	}))

	want := identityOf(t, shareable, "probe.role")

	if got := attrTextOf(t, shareable, "probe.notes"); got != want {
		t.Errorf("plain string attribute = %q, want %q: declaring an identity once "+
			"makes that token sensitive across every string-shaped surface", got, want)
	}
	if got := attrTextOf(t, shareable, "probe.list"); !strings.Contains(got, want) {
		t.Errorf("string list = %q, want it to contain %q", got, want)
	}
	// Ordinary diagnostic text is untouched, which is what makes a shareable
	// report worth reading.
	if got := attrTextOf(t, shareable, "probe.list"); !strings.Contains(got, "TLSv1.3") {
		t.Errorf("string list = %q, want TLSv1.3 preserved", got)
	}
	if strings.Contains(encode(t, shareable), canaryRole) {
		t.Errorf("raw identity %q survived in a plain string attribute", canaryRole)
	}
}

// TestUndeclaredIdentityIsNotRecognized states the honest limit of structural
// declaration, so that nobody later reads the test suite as promising more than
// the mechanism delivers.
//
// A producer that records a role as an ordinary string, and never declares it
// anywhere, leaks it. No heuristic is added to compensate: a bare role name and
// a version string are the same shape, and ADR 0022 established that guessing
// between them either leaks identity or destroys diagnostic values.
func TestUndeclaredIdentityIsNotRecognized(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role": domain.StringAttr(canaryRole),
	}))

	if got := attrTextOf(t, shareable, "probe.role"); got != canaryRole {
		t.Errorf("undeclared value = %q, want it preserved as %q; if this now redacts, "+
			"a key-name or shape heuristic was introduced and ADR 0022 forbids both",
			got, canaryRole)
	}
	if got := shareable.Security().Redactions().Identity; got != 0 {
		t.Errorf("identity count = %d, want 0: nothing was declared", got)
	}
}

// TestHostWinsWhenOneValueIsBothCategories pins the tie-break for an undeclared
// string that matches a collected value in two namespaces.
//
// The peer categories are checked first, which is what keeps every rewrite this
// package performed before Phase 4.1 byte-identical: a value that was already
// being replaced as a host is still replaced as a host, and identity only ever
// claims text no earlier category matched.
func TestHostWinsWhenOneValueIsBothCategories(t *testing.T) {
	const shared = "payments"

	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.host":  domain.HostAttr(shared),
		"probe.role":  domain.IdentityAttr(shared),
		"probe.notes": domain.StringAttr(shared),
	}))

	notes := attrTextOf(t, shareable, "probe.notes")
	if !strings.HasPrefix(notes, "host-") {
		t.Errorf("undeclared string = %q, want the host pseudonym: the peer categories "+
			"are checked first so existing behaviour cannot change", notes)
	}
	if strings.Contains(encode(t, shareable), shared) {
		t.Error("the shared raw text survived")
	}
}

// --- 20.7 prefix collision ----------------------------------------------------

// TestIdentityPrefixesDoNotCorruptEachOther is the substring hazard.
//
// Prose replacement is textual, so a shorter identity contained in a longer one
// would rewrite half of it if the order were wrong. The table sorts by
// descending length for exactly this reason, and this test is where that
// ordering is proved rather than assumed.
func TestIdentityPrefixesDoNotCorruptEachOther(t *testing.T) {
	keys := []domain.AttributeKey{"probe.ka", "probe.kb", "probe.kc", "probe.kd", "probe.ke"}
	identities := []string{"admin", "admin-prod", "prod", "production", "admin-production"}

	attrs := map[domain.AttributeKey]domain.AttrValue{}
	for i, id := range identities {
		attrs[keys[i]] = domain.IdentityAttr(id)
	}
	shareable := mustRedact(t, identityReport(t, attrs))

	seen := map[string]string{}
	for i, id := range identities {
		got := identityOf(t, shareable, keys[i])
		if !strings.HasPrefix(got, "identity-") {
			t.Errorf("%q became %q, want an identity-NNN pseudonym", id, got)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%q and %q both became %q", prev, id, got)
		}
		seen[got] = id
	}

	encoded := encode(t, shareable)
	for _, id := range identities {
		if strings.Contains(encoded, id) {
			t.Errorf("identity %q survived, or a longer value was partly rewritten "+
				"leaving it behind", id)
		}
	}
}

// --- 20.8 pseudonym-shaped raw values -----------------------------------------

// TestPseudonymShapedIdentityFailsClosedExactlyAsAHostnameDoes pins the one
// genuine limitation this namespace inherits, and proves it is inherited rather
// than introduced.
//
// The residual scan compares raw values against the finished report's string
// leaves. It cannot distinguish "this identity survived" from "a different value
// was pseudonymized to text that happens to equal it", so an identity literally
// named "host-001" or "evidence-001" is reported as surviving when it was
// replaced correctly. Redaction then refuses to produce a shareable report.
//
// That is the pre-existing behaviour of every namespace, not a new defect: the
// control below shows a *hostname* with the same text failing in exactly the
// same way at HEAD. No shape-based rule can settle the ambiguity — the raw text
// and the generated text are the same string — so none is attempted, and failing
// closed is the correct direction for a security transformation.
//
// If this test ever starts passing, the residual scan was weakened.
func TestPseudonymShapedIdentityFailsClosedExactlyAsAHostnameDoes(t *testing.T) {
	// Each of these collides with a pseudonym the fixture itself generates.
	for _, raw := range []string{"host-001", "evidence-001", "ip-001"} {
		t.Run(raw, func(t *testing.T) {
			_, identityErr := Redact(identityReport(t, map[domain.AttributeKey]domain.AttrValue{
				"probe.role": domain.IdentityAttr(raw),
			}))
			if identityErr == nil {
				t.Errorf("an identity named %q was accepted; the scan cannot tell it apart "+
					"from the generated pseudonym of the same text, so it must refuse", raw)
			}

			// The control: the same text as a hostname behaves identically, which
			// is what makes this an inherited property rather than a regression.
			_, hostErr := Redact(identityReport(t, map[domain.AttributeKey]domain.AttrValue{
				"probe.host": domain.HostAttr(raw),
			}))
			if hostErr == nil {
				t.Errorf("a hostname named %q was accepted while an identity was not; "+
					"the two namespaces must share this limitation", raw)
			}
		})
	}
}

// TestIdentityEqualToItsOwnPseudonymAlsoFailsClosed is the degenerate case: the
// raw value and the pseudonym assigned to it are the same string.
//
// The value is genuinely replaced, and the output is genuinely safe — replacing
// "identity-001" with "identity-001" discloses nothing. The scan still cannot
// prove that, so it refuses.
//
// This is deliberately *not* special-cased. An exception carved into a security
// verifier for a value nobody records would be a weakening with no user, and it
// would make the identity namespace behave differently from the host namespace
// for no reason a reader could predict.
func TestIdentityEqualToItsOwnPseudonymAlsoFailsClosed(t *testing.T) {
	_, err := Redact(identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role": domain.IdentityAttr("identity-001"),
	}))
	if err == nil {
		t.Error("expected a fail-closed refusal; if this now succeeds, a special case " +
			"was added to the residual scan")
	}
}

// --- 20.9 common report vocabulary --------------------------------------------

// TestIdentityEqualToCommonReportVocabularyIsReportedHonestly is the Phase 3.7.5
// lesson applied to the new namespace.
//
// The residual scan compares against decoded string leaves and object keys, not
// raw JSON bytes, so a short identity no longer collides with punctuation or
// with a number. It still cannot distinguish containment inside another string:
// an identity named "host" is a substring of the object key "probe.host", so it
// is reported as surviving when it has not.
//
// That fails closed rather than open. This test records exactly which values are
// usable and which are not, so the boundary is a documented property rather than
// a surprise in a real run.
func TestIdentityEqualToCommonReportVocabularyIsReportedHonestly(t *testing.T) {
	// These appear in no string position of a report built from this fixture, so
	// they redact cleanly. Short, ordinary words are usable as identities.
	clean := []string{"kafka", "postgres", "L5", "payments", "admin", "prod"}
	for _, raw := range clean {
		t.Run("clean/"+raw, func(t *testing.T) {
			local := identityReport(t, map[domain.AttributeKey]domain.AttrValue{
				"probe.role": domain.IdentityAttr(raw),
			})
			shareable, err := Redact(local)
			if err != nil {
				t.Fatalf("Redact(%q) failed closed, but nothing in the report contains it: %v",
					raw, err)
			}
			if got := identityOf(t, shareable, "probe.role"); got != "identity-001" {
				t.Errorf("identity %q became %q, want identity-001", raw, got)
			}
		})
	}

	// These are report vocabulary. "PASS" is an evidence state, "error" is a key
	// in findingCountsBySeverity, and "host" is a substring of the attribute key
	// "probe.host". The scan cannot tell a surviving identity from a coincidental
	// substring of the schema's own text, so it refuses.
	//
	// Each is paired with the same text as a hostname, which fails identically at
	// HEAD. The limitation belongs to the residual model, not to this phase.
	for _, raw := range []string{"PASS", "error", "host"} {
		t.Run("report-vocabulary/"+raw, func(t *testing.T) {
			_, identityErr := Redact(identityReport(t, map[domain.AttributeKey]domain.AttrValue{
				"probe.role": domain.IdentityAttr(raw),
			}))
			if identityErr == nil {
				t.Errorf("an identity named %q was accepted; if this now succeeds the "+
					"residual scan was weakened", raw)
			}

			_, hostErr := Redact(identityReport(t, map[domain.AttributeKey]domain.AttrValue{
				"probe.host": domain.HostAttr(raw),
			}))
			if hostErr == nil {
				t.Errorf("a hostname named %q was accepted while an identity was not; "+
					"the two namespaces must share this limitation", raw)
			}
		})
	}
}

// --- 20.10 prose --------------------------------------------------------------

// TestIdentityIsReplacedInProse pins that declared identities participate in
// prose rewriting exactly as hosts do.
//
// Findings are where a human reads the conclusion, so an identity that survived
// only in a summary would be the most likely leak of all.
func TestIdentityIsReplacedInProse(t *testing.T) {
	local := identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role": domain.IdentityAttr(canaryRole),
	})

	node := local.Graph().Nodes()[0]
	finding, err := domain.NewFinding(domain.FindingInput{
		Code:            domain.FindingCode("PROBE_SESSION_REFUSED"),
		Kind:            domain.FindingKindConfirmed,
		Severity:        domain.SeverityError,
		Confidence:      domain.ConfidenceHigh,
		Layer:           domain.LayerAuth,
		Summary:         "the endpoint refused the session for " + canaryRole,
		Detail:          "The credential presented for " + canaryRole + " was refused.",
		EvidenceRefs:    []domain.EvidenceID{node.ID()},
		Recommendations: []domain.Recommendation{mustRecommendation(t, "check "+canaryRole)},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	withFinding, err := domain.NewReport(domain.ReportInput{
		Run:      local.Run(),
		Target:   local.Target(),
		Vantage:  local.Vantage(),
		Graph:    local.Graph(),
		Findings: []domain.Finding{finding},
		Security: local.Security(),
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	shareable := mustRedact(t, withFinding)
	out := shareable.Findings()[0]
	pseudonym := identityOf(t, shareable, "probe.role")

	for name, text := range map[string]string{
		"summary":        out.Summary(),
		"detail":         out.Detail(),
		"recommendation": out.Recommendations()[0].Action(),
	} {
		if strings.Contains(text, canaryRole) {
			t.Errorf("finding %s still names the raw identity: %q", name, text)
		}
		if !strings.Contains(text, pseudonym) {
			t.Errorf("finding %s lost the correlation to %s: %q", name, pseudonym, text)
		}
	}
	if got := shareable.Security().Redactions().Prose; got != 3 {
		t.Errorf("prose count = %d, want 3 fields", got)
	}
}

// --- 20.15 empty and whitespace ------------------------------------------------

// TestEmptyIdentityIsNotGivenAPseudonym fixes the empty-value contract in the
// transformation.
//
// An absent value is not a removal. Manufacturing "identity-001" for it would
// tell a reader that something was taken out when nothing was there, and would
// consume a pseudonym that a real identity should have had.
func TestEmptyIdentityIsNotGivenAPseudonym(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.empty": domain.IdentityAttr(""),
		"probe.role":  domain.IdentityAttr(canaryRole),
	}))

	if got := identityOf(t, shareable, "probe.empty"); got != "" {
		t.Errorf("empty identity became %q, want it left empty", got)
	}
	if got := identityOf(t, shareable, "probe.role"); got != "identity-001" {
		t.Errorf("the real identity became %q, want identity-001: an empty value must not "+
			"consume a pseudonym", got)
	}
	if got := shareable.Security().Redactions().Identity; got != 1 {
		t.Errorf("identity count = %d, want 1", got)
	}
}

// TestWhitespaceIdentityIsTreatedAsAValue pins that nothing is trimmed.
//
// A whitespace-only identity is odd input, but the model does not normalize and
// neither does this package: a producer that recorded " " recorded something,
// and hosts already behave this way.
func TestWhitespaceIdentityIsTreatedAsAValue(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role": domain.IdentityAttr(" "),
	}))

	if got := identityOf(t, shareable, "probe.role"); got != "identity-001" {
		t.Errorf("whitespace identity became %q, want identity-001", got)
	}
}

// TestIdentityIsNotTrimmedOrCaseFolded proves that two identities differing only
// in case or surrounding space stay two identities.
//
// Folding them would merge two principals a server treats as distinct and would
// make a report claim a correlation that does not exist.
func TestIdentityIsNotTrimmedOrCaseFolded(t *testing.T) {
	shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.a": domain.IdentityAttr("payments"),
		"probe.b": domain.IdentityAttr("Payments"),
		"probe.c": domain.IdentityAttr(" payments"),
	}))

	seen := map[string]bool{}
	for _, key := range []domain.AttributeKey{"probe.a", "probe.b", "probe.c"} {
		got := identityOf(t, shareable, key)
		if seen[got] {
			t.Errorf("%s reused pseudonym %q: identities were normalized", key, got)
		}
		seen[got] = true
	}
	if got := shareable.Security().Redactions().Identity; got != 3 {
		t.Errorf("identity count = %d, want 3 distinct identities", got)
	}
}

// TestUnicodeIdentityRoundTrips confirms a non-ASCII identity is replaced rather
// than mangled or missed.
func TestUnicodeIdentityRoundTrips(t *testing.T) {
	for _, raw := range []string{"müşteri-yazma", "用户A", "tenant/acme", "svcdoctor@example"} {
		t.Run(raw, func(t *testing.T) {
			shareable := mustRedact(t, identityReport(t, map[domain.AttributeKey]domain.AttrValue{
				"probe.role": domain.IdentityAttr(raw),
			}))
			if got := identityOf(t, shareable, "probe.role"); got != "identity-001" {
				t.Errorf("identity %q became %q, want identity-001", raw, got)
			}
			if strings.Contains(encode(t, shareable), raw) {
				t.Errorf("raw identity %q survived", raw)
			}
		})
	}
}

// --- 20.12 / 20.13 idempotence and immutability --------------------------------

// TestIdentityRedactionIsIdempotent keeps the documented contract true for the
// new kind: redacting an already-shareable report returns it unchanged rather
// than numbering "identity-001" into "identity-002".
func TestIdentityRedactionIsIdempotent(t *testing.T) {
	local := identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role":     domain.IdentityAttr(canaryRole),
		"probe.database": domain.IdentityAttr(canaryDatabase),
	})

	once := mustRedact(t, local)
	twice := mustRedact(t, once)

	if got, want := encode(t, twice), encode(t, once); got != want {
		t.Errorf("Redact is not idempotent for identities:\n got %s\nwant %s", got, want)
	}
}

// TestRedactingDoesNotMutateTheLocalIdentityReport pins input immutability for
// the new kind. A caller that still holds the local report must be able to read
// the real identities out of it afterwards.
func TestRedactingDoesNotMutateTheLocalIdentityReport(t *testing.T) {
	local := identityReport(t, map[domain.AttributeKey]domain.AttrValue{
		"probe.role": domain.IdentityAttr(canaryRole),
	})
	before := encode(t, local)

	_ = mustRedact(t, local)

	if after := encode(t, local); after != before {
		t.Errorf("the local report changed:\nbefore %s\n after %s", before, after)
	}
	if got := identityOf(t, local, "probe.role"); got != canaryRole {
		t.Errorf("the local report's identity is now %q, want %q", got, canaryRole)
	}
	if local.Security().OutputMode() != domain.OutputModeLocalFull {
		t.Error("the local report's output mode changed")
	}
}

// --- 20.15 fail-closed ---------------------------------------------------------

// TestResidualScanCatchesASurvivingIdentity is the fail-closed proof for the new
// namespace, and it does not rely on the happy path.
//
// It plants a raw identity into a report that is otherwise fully redacted and
// checks the verifier by itself, which is the same technique the host and IP
// cases already use.
func TestResidualScanCatchesASurvivingIdentity(t *testing.T) {
	surfaces := map[string]func(map[domain.AttributeKey]domain.AttrValue){
		"identity attribute": func(a map[domain.AttributeKey]domain.AttrValue) {
			a["probe.role"] = domain.IdentityAttr(residualIdent)
		},
		"plain string attribute": func(a map[domain.AttributeKey]domain.AttrValue) {
			a["probe.notes"] = domain.StringAttr(residualIdent)
		},
		"string list attribute": func(a map[domain.AttributeKey]domain.AttrValue) {
			a["probe.list"] = domain.StringListAttr("ok", residualIdent)
		},
	}

	for name, plant := range surfaces {
		t.Run(name, func(t *testing.T) {
			attrs := map[domain.AttributeKey]domain.AttrValue{}
			plant(attrs)
			// A report that already looks redacted everywhere else, so only the
			// planted value can trip the scan.
			planted := plantedReport(t, "", "", "", "", "", "", nil)
			rebuilt := replaceNodeAttributes(t, planted, attrs)

			if err := verifyNoResidual(residualTable(), rebuilt); err == nil {
				t.Errorf("a raw identity in the %s was not caught; redaction would have "+
					"produced a report labelled SHAREABLE_REDACTED containing %q",
					name, residualIdent)
			}
		})
	}
}

// TestResidualScanAcceptsAReportWithNoSurvivingIdentity is the control for the
// matrix above: it proves those failures came from the planted value rather than
// from the scan rejecting everything.
func TestResidualScanAcceptsAReportWithNoSurvivingIdentity(t *testing.T) {
	clean := plantedReport(t, "", "", "", "", "", "", nil)
	if err := verifyNoResidual(residualTable(), clean); err != nil {
		t.Errorf("a clean report was rejected: %v", err)
	}
}

// replaceNodeAttributes rebuilds a one-node report with different attributes,
// keeping every other field, so a test can plant a value without reassembling a
// whole fixture.
func replaceNodeAttributes(
	t *testing.T, report domain.Report, attrs map[domain.AttributeKey]domain.AttrValue,
) domain.Report {
	t.Helper()

	node := report.Graph().Nodes()[0]
	rebuilt, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           node.ID(),
		Subject:      node.Subject(),
		Layer:        node.Layer(),
		Step:         node.Step(),
		State:        node.State(),
		FailureClass: node.FailureClass(),
		Attributes:   attrs,
		StartedAt:    node.StartedAt(),
		Duration:     node.Duration(),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(rebuilt); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out, err := domain.NewReport(domain.ReportInput{
		Run:      report.Run(),
		Target:   report.Target(),
		Vantage:  report.Vantage(),
		Graph:    graph,
		Security: report.Security(),
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return out
}

// --- regression: nothing without identities changed ----------------------------

// TestReportWithoutIdentitiesReportsZero is the compatibility guard.
//
// Every report svcdoctor produced before this phase carries no identity
// attribute, so its counts must read exactly as they did, with the new category
// at zero and the other four untouched.
func TestReportWithoutIdentitiesReportsZero(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	counts := shareable.Security().Redactions()
	if counts.Identity != 0 {
		t.Errorf("identity count = %d, want 0 for a report with no identity attributes",
			counts.Identity)
	}
	if counts.Hostname == 0 || counts.EvidenceID == 0 {
		t.Fatalf("fixture is not exercising redaction: %+v", counts)
	}

	encoded := encode(t, shareable.Security())
	if !strings.Contains(encoded, `"identity":0`) {
		t.Errorf("security metadata = %s, want an explicit identity count; "+
			"the struct documents that it has no missing keys", encoded)
	}
}

// TestLocalReportStillCarriesNoCounts proves the LOCAL_FULL encoding is
// untouched by this phase.
//
// Counts appear only on a shareable report, so every local report svcdoctor has
// ever written serializes byte-identically before and after Phase 4.1.
func TestLocalReportStillCarriesNoCounts(t *testing.T) {
	encoded := encode(t, localReport(t).Security())
	if strings.Contains(encoded, "redactions") || strings.Contains(encoded, "identity") {
		t.Errorf("a local report gained redaction metadata: %s", encoded)
	}
}
