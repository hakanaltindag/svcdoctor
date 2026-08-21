package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// canary is a distinctive value that must never appear in any output path.
//
// Every leak assertion in this package checks for the absence of this exact
// string rather than checking that output "looks masked". A masked-looking
// string can still be accompanied by the real value elsewhere in the output.
const canary = "svcdoctor-canary-secret-9f3c7a"

// assertNoCanary fails if the canary appears anywhere in got.
func assertNoCanary(t *testing.T, path, got string) {
	t.Helper()
	if strings.Contains(got, canary) {
		t.Errorf("secret leaked through %s\noutput: %q", path, got)
	}
}

func testCredential(t *testing.T) Credential {
	t.Helper()
	ep, err := NewEndpoint("broker-1.internal", 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	cred, err := NewCredential(ep, "svc_app", NewSecret(canary))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred
}

// TestSecretLeakPaths sweeps every formatting and serialization path a Secret
// can reach on its own.
func TestSecretLeakPaths(t *testing.T) {
	s := NewSecret(canary)

	// A struct wrapper, to prove that a Secret nested in a struct is still
	// intercepted when fmt walks fields.
	type wrapper struct {
		Name   string
		Secret Secret
	}
	w := wrapper{Name: "kafka", Secret: s}

	jsonSecret, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal(Secret): %v", err)
	}
	jsonWrapper, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("json.Marshal(wrapper): %v", err)
	}
	jsonIndented, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent(wrapper): %v", err)
	}
	textSecret, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	jsonMapKey, err := json.Marshal(map[string]Secret{"password": s})
	if err != nil {
		t.Fatalf("json.Marshal(map): %v", err)
	}

	// Variable format strings so vet's printf analysis does not reject these
	// deliberate misuses. %p and %T bypass fmt.Formatter entirely, and %p on a
	// non-pointer operand reaches fmt's reflection-based badVerb path.
	pointerVerb := "%p"
	typeVerb := "%T"

	paths := []struct {
		path string
		got  string
	}{
		{`Secret.String()`, s.String()},
		{`Secret.GoString()`, s.GoString()},
		{`fmt.Sprintf("%s", secret)`, fmt.Sprintf("%s", s)},
		{`fmt.Sprintf("%v", secret)`, fmt.Sprintf("%v", s)},
		{`fmt.Sprintf("%+v", secret)`, fmt.Sprintf("%+v", s)},
		{`fmt.Sprintf("%#v", secret)`, fmt.Sprintf("%#v", s)},
		{`fmt.Sprintf("%q", secret)`, fmt.Sprintf("%q", s)},
		{`fmt.Sprintf("%x", secret)`, fmt.Sprintf("%x", s)},
		{`fmt.Sprintf("%X", secret)`, fmt.Sprintf("%X", s)},
		{`fmt.Sprintf("%d", secret)`, fmt.Sprintf("%d", s)},
		{`fmt.Sprintf("%t", secret)`, fmt.Sprintf("%t", s)},
		{`fmt.Sprintf("%p", secret)`, fmt.Sprintf(pointerVerb, s)},
		//nolint:staticcheck // SA5009: %p on a struct is the misuse under test.
		{`fmt.Sprintf("%p", struct)`, fmt.Sprintf(pointerVerb, w)},
		{`fmt.Sprintf("%p", []Secret)`, fmt.Sprintf(pointerVerb, []Secret{s})},
		{`fmt.Sprintf("%p", map[string]Secret)`, fmt.Sprintf(pointerVerb, map[string]Secret{"pw": s})},
		{`fmt.Sprintf("%T", secret)`, fmt.Sprintf(typeVerb, s)},
		{`fmt.Sprint(secret)`, fmt.Sprint(s)},
		{`fmt.Sprintln(secret)`, fmt.Sprintln(s)},
		{`fmt.Sprintf("%v", &secret)`, fmt.Sprintf("%v", &s)},
		{`fmt.Sprintf("%v", struct)`, fmt.Sprintf("%v", w)},
		{`fmt.Sprintf("%+v", struct)`, fmt.Sprintf("%+v", w)},
		{`fmt.Sprintf("%#v", struct)`, fmt.Sprintf("%#v", w)},
		{`fmt.Sprintf("%v", []Secret)`, fmt.Sprintf("%v", []Secret{s})},
		{`fmt.Sprintf("%v", map[string]Secret)`, fmt.Sprintf("%v", map[string]Secret{"pw": s})},
		{`json.Marshal(Secret)`, string(jsonSecret)},
		{`json.Marshal(struct)`, string(jsonWrapper)},
		{`json.MarshalIndent(struct)`, string(jsonIndented)},
		{`json.Marshal(map[string]Secret)`, string(jsonMapKey)},
		{`Secret.MarshalText()`, string(textSecret)},
	}

	for _, p := range paths {
		assertNoCanary(t, p.path, p.got)
	}
}

// TestCredentialLeakPaths sweeps the paths a Credential can reach, including
// the ones that walk its embedded Secret.
func TestCredentialLeakPaths(t *testing.T) {
	cred := testCredential(t)

	type wrapper struct {
		Service    string
		Credential Credential
	}
	w := wrapper{Service: "kafka", Credential: cred}

	// SA9005 correctly notes that Credential has no exported fields and no
	// custom marshaling, so this always yields "{}". That is the designed
	// behavior, asserted in TestCredentialMarshalsToEmptyObject; here it is
	// swept for the canary like every other output path.
	//nolint:staticcheck // SA9005: the empty result is the property under test.
	jsonCred, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("json.Marshal(Credential): %v", err)
	}
	jsonWrapper, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("json.Marshal(wrapper): %v", err)
	}

	pointerVerb := "%p"
	typeVerb := "%T"

	paths := []struct {
		path string
		got  string
	}{
		{`Credential.String()`, cred.String()},
		{`fmt.Sprintf("%p", cred)`, fmt.Sprintf(pointerVerb, cred)},
		//nolint:staticcheck // SA5009: %p on a struct is the misuse under test.
		{`fmt.Sprintf("%p", struct)`, fmt.Sprintf(pointerVerb, w)},
		{`fmt.Sprintf("%T", cred)`, fmt.Sprintf(typeVerb, cred)},
		{`Credential.GoString()`, cred.GoString()},
		{`fmt.Sprintf("%s", cred)`, fmt.Sprintf("%s", cred)},
		{`fmt.Sprintf("%v", cred)`, fmt.Sprintf("%v", cred)},
		{`fmt.Sprintf("%+v", cred)`, fmt.Sprintf("%+v", cred)},
		{`fmt.Sprintf("%#v", cred)`, fmt.Sprintf("%#v", cred)},
		{`fmt.Sprintf("%q", cred)`, fmt.Sprintf("%q", cred)},
		{`fmt.Sprintf("%d", cred)`, fmt.Sprintf("%d", cred)},
		{`fmt.Sprint(cred)`, fmt.Sprint(cred)},
		{`fmt.Sprintf("%v", &cred)`, fmt.Sprintf("%v", &cred)},
		{`fmt.Sprintf("%+v", struct)`, fmt.Sprintf("%+v", w)},
		{`fmt.Sprintf("%#v", struct)`, fmt.Sprintf("%#v", w)},
		{`fmt.Sprintf("%v", []Credential)`, fmt.Sprintf("%v", []Credential{cred})},
		{`json.Marshal(Credential)`, string(jsonCred)},
		{`json.Marshal(struct)`, string(jsonWrapper)},
	}

	for _, p := range paths {
		assertNoCanary(t, p.path, p.got)
	}
}

// TestErrorPathsDoNotLeak covers error construction and wrapping, which is the
// most common accidental leak route in Go: a credential interpolated into an
// error message that later reaches a log or a report.
func TestErrorPathsDoNotLeak(t *testing.T) {
	cred := testCredential(t)
	secret := NewSecret(canary)

	other, err := NewEndpoint("broker-2.internal", 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}

	// The mismatch error produced by the package itself.
	_, mismatchErr := cred.SecretFor(other)
	if mismatchErr == nil {
		t.Fatal("SecretFor on a mismatched endpoint returned no error")
	}

	// Errors a caller might plausibly build.
	credErr := fmt.Errorf("authentication failed for %v", cred)
	secretErr := fmt.Errorf("authentication failed with %s", secret)
	wrapped := fmt.Errorf("kafka: %w", fmt.Errorf("sasl: %w", credErr))
	joined := errors.Join(mismatchErr, credErr, secretErr)

	paths := []struct {
		path string
		got  string
	}{
		{`SecretFor mismatch error`, mismatchErr.Error()},
		{`fmt.Sprintf("%v", mismatchErr)`, fmt.Sprintf("%v", mismatchErr)},
		{`fmt.Errorf with Credential`, credErr.Error()},
		{`fmt.Errorf with Secret`, secretErr.Error()},
		{`doubly wrapped error`, wrapped.Error()},
		{`fmt.Sprintf("%+v", wrapped)`, fmt.Sprintf("%+v", wrapped)},
		{`errors.Join`, joined.Error()},
	}

	for _, p := range paths {
		assertNoCanary(t, p.path, p.got)
	}
}

// TestRevealIsTheOnlyDisclosure documents the escape hatch explicitly: Reveal
// returns plaintext, and nothing else in the package does.
func TestRevealIsTheOnlyDisclosure(t *testing.T) {
	s := NewSecret(canary)

	if got := Reveal(s); got != canary {
		t.Errorf("Reveal returned %q, want the plaintext", got)
	}

	// The zero Secret reveals nothing.
	if got := Reveal(Secret{}); got != "" {
		t.Errorf("Reveal(zero) = %q, want empty", got)
	}
}
