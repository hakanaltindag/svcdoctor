package security

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSecretMaskedRepresentations(t *testing.T) {
	s := NewSecret("hunter2")

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"String", s.String(), "***"},
		{"%s", fmt.Sprintf("%s", s), "***"},
		{"%v", fmt.Sprintf("%v", s), "***"},
		{"%+v", fmt.Sprintf("%+v", s), "***"},
		{"%q", fmt.Sprintf("%q", s), `"***"`},
		{"%#v", fmt.Sprintf("%#v", s), "security.Secret{/* redacted */}"},
		{"GoString", s.GoString(), "security.Secret{/* redacted */}"},
		// Verbs that make no sense for a Secret still return the mask rather
		// than a fmt error string, because a fmt error string embeds the operand.
		{"%d", fmt.Sprintf("%d", s), "***"},
		{"%x", fmt.Sprintf("%x", s), "***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSecretJSON(t *testing.T) {
	s := NewSecret("hunter2")

	got, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != `"***"` {
		t.Errorf("json.Marshal(Secret) = %s, want \"***\"", got)
	}

	type config struct {
		User     string `json:"user"`
		Password Secret `json:"password"`
	}
	got, err = json.Marshal(config{User: "svc_app", Password: s})
	if err != nil {
		t.Fatalf("json.Marshal(config): %v", err)
	}
	want := `{"user":"svc_app","password":"***"}`
	if string(got) != want {
		t.Errorf("json.Marshal(config) = %s, want %s", got, want)
	}
}

func TestSecretText(t *testing.T) {
	got, err := NewSecret("hunter2").MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(got) != "***" {
		t.Errorf("MarshalText = %q, want %q", got, "***")
	}
}

func TestSecretZeroValueIsUsable(t *testing.T) {
	var s Secret

	if !s.IsEmpty() {
		t.Error("zero Secret should report IsEmpty")
	}
	if s.String() != "***" {
		t.Errorf("zero Secret String = %q, want %q", s.String(), "***")
	}
	if Reveal(s) != "" {
		t.Error("zero Secret should reveal an empty string")
	}
}

func TestSecretIsEmpty(t *testing.T) {
	if NewSecret("").IsEmpty() != true {
		t.Error(`NewSecret("") should be empty`)
	}
	if NewSecret("x").IsEmpty() != false {
		t.Error(`NewSecret("x") should not be empty`)
	}
}

// TestSecretDoesNotLeakThroughReflection pins the reason Secret holds its
// plaintext behind a pointer.
//
// fmt resolves %p and %T before consulting Formatter, so Secret.Format never
// runs for them. %p on a non-pointer operand then enters fmt's badVerb path,
// which disables method handling and prints the operand by reflection,
// including unexported fields. The pointer indirection makes that walk print an
// address rather than the value.
func TestSecretDoesNotLeakThroughReflection(t *testing.T) {
	const plaintext = "reflection-probe-value"
	s := NewSecret(plaintext)

	type wrapper struct {
		Name   string
		Secret Secret
	}

	// The format string is a variable so that vet's printf analysis does not
	// reject these deliberate misuses at compile time. That also mirrors the
	// real risk: a dynamically assembled format string is exactly the case
	// static analysis cannot protect a caller from.
	pointerVerb := "%p"
	typeVerb := "%T"

	got := []string{
		fmt.Sprintf(pointerVerb, s),
		//nolint:staticcheck // SA5009: %p on a struct is the misuse under test.
		fmt.Sprintf(pointerVerb, wrapper{Name: "kafka", Secret: s}),
		fmt.Sprintf(pointerVerb, []Secret{s}),
		fmt.Sprintf(pointerVerb, map[string]Secret{"pw": s}),
		fmt.Sprintf(typeVerb, s),
	}

	for _, out := range got {
		if strings.Contains(out, plaintext) {
			t.Errorf("plaintext reached a reflection path: %q", out)
		}
	}
}

// TestSecretCannotBeUnmarshalled prevents a value in a config or report file
// from being turned into a usable Secret.
//
// Secret implements no json.Unmarshaler and has no exported fields, so
// encoding/json rejects the attempt outright rather than silently ignoring it.
func TestSecretCannotBeUnmarshalled(t *testing.T) {
	type config struct {
		Password Secret `json:"password"`
	}

	var c config
	err := json.Unmarshal([]byte(`{"password":"hunter2"}`), &c)
	if err == nil {
		t.Fatal("unmarshalling into a Secret should fail, got no error")
	}
	if !c.Password.IsEmpty() {
		t.Error("a failed unmarshal must leave the Secret empty")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the unmarshal error leaked the input value: %q", err)
	}
}
