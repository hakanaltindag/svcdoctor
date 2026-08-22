package domain

import (
	"encoding/json"
	"testing"
)

// Identity canaries. They are deliberately shaped like the values a future
// service adapter would record — a role, a database, a tenant — without this
// package knowing that any such service exists.
const (
	identityRole     = "payments_writer"
	identityDatabase = "payments_prod"
)

// TestIdentityAttrCarriesItsValue pins the constructor, the kind and the
// accessor together, because a value that reports the wrong kind would be
// rewritten through the wrong pseudonym namespace by redaction.
func TestIdentityAttrCarriesItsValue(t *testing.T) {
	v := IdentityAttr(identityRole)

	if got := v.Kind(); got != AttrKindIdentity {
		t.Errorf("Kind() = %s, want %s", got, AttrKindIdentity)
	}
	if !v.Valid() {
		t.Error("IdentityAttr produced an invalid value")
	}
	got, ok := v.Identity()
	if !ok {
		t.Fatal("Identity() reported no identity")
	}
	if got != identityRole {
		t.Errorf("Identity() = %q, want %q", got, identityRole)
	}
}

// TestIdentityAccessorsAreKindExclusive is the reason every accessor returns a
// second result. An identity read as a host, or a host read as an identity,
// would be routed into the wrong namespace and could be numbered as a machine.
func TestIdentityAccessorsAreKindExclusive(t *testing.T) {
	identity := IdentityAttr(identityRole)
	if _, ok := identity.Host(); ok {
		t.Error("Host() accepted an identity value")
	}
	if _, ok := identity.Str(); ok {
		t.Error("Str() accepted an identity value")
	}
	if _, ok := identity.HostList(); ok {
		t.Error("HostList() accepted an identity value")
	}

	for name, other := range map[string]AttrValue{
		"string":     StringAttr(identityRole),
		"host":       HostAttr(identityRole),
		"hostList":   HostListAttr(identityRole),
		"stringList": StringListAttr(identityRole),
		"int":        IntAttr(1),
		"bool":       BoolAttr(true),
	} {
		if _, ok := other.Identity(); ok {
			t.Errorf("Identity() accepted a %s value", name)
		}
	}
}

// TestIdentityValueIsNotNormalized pins that the model stores exactly what a
// producer recorded.
//
// Normalization here would be a security defect rather than a convenience: two
// principals a server treats as distinct would collapse onto one pseudonym, and
// a report would then claim a correlation that does not exist. Equality stays
// string equality.
func TestIdentityValueIsNotNormalized(t *testing.T) {
	cases := []string{
		identityRole,
		"Payments_Writer",
		"  payments_writer  ",
		"payments writer",
		"tenant/acme",
		"svcdoctor@example",
		"müşteri-yazma",
		"用户A",
		"identity-001",
		"host-001",
		"PASS",
		"",
	}

	for _, want := range cases {
		got, ok := IdentityAttr(want).Identity()
		if !ok {
			t.Errorf("Identity() reported no identity for %q", want)
			continue
		}
		if got != want {
			t.Errorf("Identity() = %q, want %q", got, want)
		}
	}
}

// TestEmptyIdentityIsAValidValueHoldingNothing fixes the empty-value contract at
// the model boundary.
//
// It matches HostAttr("") exactly, which is the precedent that decides it: the
// kind is what makes an AttrValue valid, so an empty declared value is
// representable and carries no identity. What redaction does with it is pinned
// separately, next to the transformation.
func TestEmptyIdentityIsAValidValueHoldingNothing(t *testing.T) {
	empty := IdentityAttr("")

	if !empty.Valid() {
		t.Error("IdentityAttr(\"\") is invalid; HostAttr(\"\") is valid and the two must agree")
	}
	if got := empty.Kind(); got != AttrKindIdentity {
		t.Errorf("Kind() = %s, want %s", got, AttrKindIdentity)
	}
	got, ok := empty.Identity()
	if !ok || got != "" {
		t.Errorf("Identity() = %q, %v; want \"\", true", got, ok)
	}

	// The evidence constructor accepts it for the same reason it accepts an
	// empty host: validity is a property of the kind.
	if _, err := copyAttributes(map[AttributeKey]AttrValue{"probe.role": empty}); err != nil {
		t.Errorf("an empty identity was rejected as an attribute: %v", err)
	}
}

// TestIdentityMarshalsAsATaggedValue pins the wire form. The tag is what lets a
// redactor find the value without guessing at its shape, so it is contract.
func TestIdentityMarshalsAsATaggedValue(t *testing.T) {
	encoded, err := json.Marshal(IdentityAttr(identityDatabase))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	want := `{"kind":"identity","value":"payments_prod"}`
	if got := string(encoded); got != want {
		t.Errorf("encoded = %s, want %s", got, want)
	}

	empty, err := json.Marshal(IdentityAttr(""))
	if err != nil {
		t.Fatalf("MarshalJSON of an empty identity: %v", err)
	}
	if got, want := string(empty), `{"kind":"identity","value":""}`; got != want {
		t.Errorf("encoded empty = %s, want %s", got, want)
	}
}

// TestIdentityKindTagIsTheContract pins the tag text itself. Renaming it would
// silently change every shareable report a machine consumer parses.
func TestIdentityKindTagIsTheContract(t *testing.T) {
	if got := AttrKindIdentity.String(); got != "identity" {
		t.Errorf("AttrKindIdentity.String() = %q, want %q", got, "identity")
	}
}

// TestExistingAttrKindTagsAreUnchanged is the compatibility guard for Phase 4.1.
//
// Adding a kind must not renumber or rename an existing one: the tag travels in
// every report, and an ordinal shift would change how a value already written to
// disk decodes. The new kind is appended, so every value below keeps its place.
func TestExistingAttrKindTagsAreUnchanged(t *testing.T) {
	want := []struct {
		kind AttrKind
		name string
	}{
		{AttrKindInvalid, "invalid"},
		{AttrKindString, "string"},
		{AttrKindInt, "int"},
		{AttrKindBool, "bool"},
		{AttrKindDuration, "duration"},
		{AttrKindTime, "time"},
		{AttrKindStringList, "stringList"},
		{AttrKindHost, "host"},
		{AttrKindHostList, "hostList"},
		{AttrKindIdentity, "identity"},
	}

	for i, tc := range want {
		if int(tc.kind) != i {
			t.Errorf("%s has ordinal %d, want %d: an existing kind was renumbered",
				tc.name, tc.kind, i)
		}
		if got := tc.kind.String(); got != tc.name {
			t.Errorf("AttrKind(%d).String() = %q, want %q", i, got, tc.name)
		}
	}
}

// TestIdentityAndHostAreDifferentValues is the semantic boundary in the model.
//
// The same text recorded through the two constructors produces two values that
// are not equal and do not report each other's kind. That is what stops a
// database from being described as a network peer, which would render as
// "host-002" and send a reader looking for a machine.
func TestIdentityAndHostAreDifferentValues(t *testing.T) {
	const shared = "payments"

	identity := IdentityAttr(shared)
	host := HostAttr(shared)

	if identity.Kind() == host.Kind() {
		t.Error("an identity and a host reported the same kind")
	}
	if _, ok := identity.Host(); ok {
		t.Error("an identity reported itself as a host")
	}
	if _, ok := host.Identity(); ok {
		t.Error("a host reported itself as an identity")
	}
	// Both render the same in logs, which is correct: the difference is a claim
	// about what the value is, not about how it reads.
	if identity.String() != host.String() {
		t.Errorf("String() differs: %q vs %q", identity.String(), host.String())
	}
}

// TestRedactionCountsIncludeIdentity pins the count field and the total.
//
// Total is what a renderer uses to say "redaction happened", so an identity that
// did not reach it would let a report claim nothing was removed.
func TestRedactionCountsIncludeIdentity(t *testing.T) {
	counts := RedactionCounts{Hostname: 1, IPAddress: 2, EvidenceID: 3, Prose: 4, Identity: 5}
	if got, want := counts.Total(), 15; got != want {
		t.Errorf("Total() = %d, want %d", got, want)
	}

	only := RedactionCounts{Identity: 1}
	if got := only.Total(); got != 1 {
		t.Errorf("Total() with only identities = %d, want 1", got)
	}
}

// TestShareableSecurityRejectsNegativeIdentityCount keeps the new field inside
// the validation the other four already have.
func TestShareableSecurityRejectsNegativeIdentityCount(t *testing.T) {
	local, err := NewReportSecurity(OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	if _, err := NewShareableReportSecurity(local, RedactionCounts{Identity: -1}); err == nil {
		t.Error("a negative identity count was accepted")
	}
}

// TestRedactionCountsEncodeIdentityLast pins the serialized shape.
//
// The four existing keys keep their names and their order, and identity is
// appended. A local report is unaffected: it carries no counts at all, which is
// what keeps every pre-Phase-4.1 LOCAL_FULL report byte-identical.
func TestRedactionCountsEncodeIdentityLast(t *testing.T) {
	encoded, err := json.Marshal(RedactionCounts{
		Hostname: 3, IPAddress: 1, EvidenceID: 3, Prose: 4, Identity: 2,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"hostname":3,"ipAddress":1,"evidenceId":3,"prose":4,"identity":2}`
	if got := string(encoded); got != want {
		t.Errorf("encoded = %s, want %s", got, want)
	}
}
