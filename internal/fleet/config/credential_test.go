package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// The credential-reference matrix.
//
// ADR 0072 section 2's table is the contract, and every row of it is a case
// here. The refusals matter more than the acceptances: this is the type whose
// job is to make a plaintext password in a configuration file impossible to
// write rather than merely discouraged.

// withPassword builds a one-target document carrying a raw password block.
func withPassword(block string) string {
	return "version: 1\ntargets:\n  - id: t\n    type: redis\n" +
		"    host: h.example.com\n    credentials:\n      username: u\n" + block
}

// plaintextCanary is the value a misbehaving implementation would echo.
const plaintextCanary = "hunter2-PLAINTEXT-CANARY"

// TestMTC05AndC18APlaintextPasswordIsRefusedStructurally is MT-C05 and MT-C18.
//
// # This is the single most important refusal in the package
//
// ADR 0072 section 3 requires it to be structural rather than a check, because a
// check is something that can be moved, reordered or forgotten — and the thing
// forgotten would be a plaintext password committed to a repository.
//
// Every scalar shape is here, because "a password" is written in more ways than
// one and a refusal that only covers the unquoted form is not a refusal.
func TestMTC05AndC18APlaintextPasswordIsRefusedStructurally(t *testing.T) {
	shapes := []struct{ name, block string }{
		{"bare scalar", "      password: " + plaintextCanary + "\n"},
		{"double quoted", "      password: \"" + plaintextCanary + "\"\n"},
		{"single quoted", "      password: '" + plaintextCanary + "'\n"},
		{"block scalar", "      password: |\n        " + plaintextCanary + "\n"},
		{"folded scalar", "      password: >\n        " + plaintextCanary + "\n"},
		{"integer", "      password: 12345\n"},
		{"boolean", "      password: true\n"},
		{"list", "      password:\n        - " + plaintextCanary + "\n"},
		{"list of mappings", "      password:\n        - env: E\n"},
	}

	for _, tt := range shapes {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, withPassword(tt.block))
			assertCategory(t, err, config.CategoryCredentialReference)

			// The refusal must explain the model rather than only complaining
			// about a type, because the operator's next action is to move the
			// secret out of the file entirely.
			if !strings.Contains(err.Error(), "env") || !strings.Contains(err.Error(), "file") {
				t.Errorf("err = %v, want the two supported sources named", err)
			}

			// And it must not echo what was written. yaml.v3 interpolates the
			// offending scalar into its own type errors, so this is the case
			// that would leak a password onto the terminal.
			for _, rendered := range []string{
				err.Error(),
				fmt.Sprintf("%v", err),
				fmt.Sprintf("%+v", err),
				fmt.Sprintf("%#v", err),
			} {
				if strings.Contains(rendered, plaintextCanary) {
					t.Errorf("the refusal echoed the plaintext password: %s", rendered)
				}
			}
		})
	}
}

// TestAPlaintextCredentialsBlockIsRefusedWithoutEchoing covers the neighbouring
// position.
//
// An operator who puts a password one level up — `credentials: hunter2` — is
// making the same mistake, and the general sanitizer rather than the credential
// interceptor is what keeps that message clean.
func TestAPlaintextCredentialsBlockIsRefusedWithoutEchoing(t *testing.T) {
	_, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: redis\n"+
		"    host: h.example.com\n    credentials: "+plaintextCanary+"\n")
	if err == nil {
		t.Fatal("a scalar credentials block was accepted")
	}
	if strings.Contains(err.Error(), plaintextCanary) {
		t.Errorf("the refusal echoed the value: %v", err)
	}
}

// TestASanitizedDecoderErrorNeverEchoesAScalar is the general guarantee.
//
// Not the credential position — an arbitrary field whose type is wrong. The
// sanitizer exists so that a password written anywhere at all, including a place
// this schema has not imagined, cannot reach an operator's terminal.
func TestASanitizedDecoderErrorNeverEchoesAScalar(t *testing.T) {
	docs := []string{
		"version: 1\ntargets: " + plaintextCanary + "\n",
		"version: 1\ntargets:\n  - id: t\n    type: redis\n    host: h.example.com\n" +
			"    tls: " + plaintextCanary + "\n",
		"version: 1\nrun: " + plaintextCanary + "\ntargets:\n  - id: t\n    type: redis\n" +
			"    host: h.example.com\n",
	}
	for i, doc := range docs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, err := load(t, doc)
			if err == nil {
				t.Fatal("want a refusal")
			}
			if strings.Contains(err.Error(), plaintextCanary) {
				t.Errorf("a decoder error echoed a scalar: %v", err)
			}
			// The type information survives, because that is the part that
			// explains the defect.
			if !strings.Contains(err.Error(), "redacted") &&
				!strings.Contains(err.Error(), "not found") {
				t.Logf("message: %v", err)
			}
		})
	}
}

// TestMTC19BothSourcesAreRefused is MT-C19.
func TestMTC19BothSourcesAreRefused(t *testing.T) {
	_, err := load(t, withPassword("      password:\n        env: E\n        file: /f\n"))
	assertCategory(t, err, config.CategoryCredentialReference)
	if !strings.Contains(err.Error(), "no precedence") {
		t.Errorf("err = %v, want the refusal to say why there is no precedence", err)
	}
}

// TestMTC20NeitherSourceIsRefused is MT-C20, in both spellings.
func TestMTC20NeitherSourceIsRefused(t *testing.T) {
	tests := []struct{ name, block string }{
		{"empty mapping", "      password: {}\n"},
		{"explicit null", "      password:\n"},
		{"tilde", "      password: ~\n"},
		{"null keyword", "      password: null\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, withPassword(tt.block))
			assertCategory(t, err, config.CategoryCredentialReference)
			if !strings.Contains(err.Error(), "names no source") {
				t.Errorf("err = %v, want a names-no-source refusal", err)
			}
		})
	}
}

// TestAnAbsentPasswordIsAValidRun is the other half of MT-C20.
//
// ADR 0072 section 2: an absent password is a supported run, not a degraded one.
// It reaches its endpoint and produces <SERVICE>_CREDENTIAL_NOT_CONFIGURED, a
// WARN at exit 0 — one of the three load-bearing product invariants. Refusing it
// here would break that from the configuration layer.
func TestAnAbsentPasswordIsAValidRun(t *testing.T) {
	cfg, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: redis\n"+
		"    host: h.example.com\n    credentials:\n      username: u\n")
	if err != nil {
		t.Fatalf("a target with an identity and no password must be valid: %v", err)
	}
	if !cfg.Targets[0].Credentials.Password.IsZero() {
		t.Error("want no reference")
	}
	if got, want := cfg.Targets[0].Credentials.Username, "u"; got != want {
		t.Errorf("Username = %q, want %q", got, want)
	}
}

// TestNoCredentialsBlockAtAllIsValid is the same for the whole block.
func TestNoCredentialsBlockAtAllIsValid(t *testing.T) {
	cfg, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: redis\n    host: h.example.com\n")
	if err != nil {
		t.Fatalf("a target with no credentials block must be valid: %v", err)
	}
	if !cfg.Targets[0].Credentials.Password.IsZero() {
		t.Error("want no reference")
	}
}

// TestMTC07EnvNameGrammar is MT-C07's structural half, and MT-S07's.
func TestMTC07EnvNameGrammar(t *testing.T) {
	valid := []string{"E", "_", "DB_PASSWORD", "db_password", "P1", "_1", "A_1_B"}
	for _, name := range valid {
		t.Run("valid/"+name, func(t *testing.T) {
			if _, err := load(t, withPassword("      password:\n        env: "+name+"\n")); err != nil {
				t.Errorf("env %q was refused: %v", name, err)
			}
		})
	}

	invalid := []struct{ name, env, want string }{
		{"interpolation", "${DB_PASSWORD}", "no variable expansion"},
		{"dollar prefix", "$DB_PASSWORD", "no variable expansion"},
		{"leading digit", "1DB", "may not begin with a digit"},
		{"hyphen", "DB-PASSWORD", "only letters, digits and underscore"},
		{"dot", "DB.PASSWORD", "only letters, digits and underscore"},
		{"space", "\"DB PASSWORD\"", "only letters, digits and underscore"},
		{"equals", "\"DB=PASSWORD\"", "only letters, digits and underscore"},
		{"slash", "DB/PASSWORD", "only letters, digits and underscore"},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			_, err := load(t, withPassword("      password:\n        env: "+tt.env+"\n"))
			assertCategory(t, err, config.CategoryCredentialReference)
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}

	t.Run("an over-long name is refused", func(t *testing.T) {
		_, err := load(t, withPassword(
			"      password:\n        env: "+strings.Repeat("A", 129)+"\n"))
		assertCategory(t, err, config.CategoryCredentialReference)
	})
}

// TestMTS07ArbitraryInterpolationIsAbsentEverywhere is MT-S07.
//
// ADR 0071 section 8.3 refuses `${VAR}` anywhere in a configuration, not only in
// a credential reference. The proof for every other field is that the value
// arrives **verbatim**: nothing expands it, so a document that names a variable
// gets a host, a database or a virtual host with braces in it — and then fails
// at the layer that actually uses it, having made no substitution.
func TestMTS07ArbitraryInterpolationIsAbsentEverywhere(t *testing.T) {
	t.Setenv("SVCDOCTOR_TEST_HOST", "secret-host.internal")
	t.Setenv("DB", "secretdb")

	cfg, err := load(t, `
version: 1
targets:
  - id: t
    type: postgres
    host: "${SVCDOCTOR_TEST_HOST}"
    credentials:
      username: "$DB"
    config:
      database: "${DB}"
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got, want := cfg.Targets[0].Host, "${SVCDOCTOR_TEST_HOST}"; got != want {
		t.Errorf("Host = %q, want it verbatim as %q", got, want)
	}
	if got, want := cfg.Targets[0].Credentials.Username, "$DB"; got != want {
		t.Errorf("Username = %q, want it verbatim as %q", got, want)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "secret-host.internal") {
		t.Error("an environment value was interpolated into the configuration")
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "secretdb") {
		t.Error("an environment value was interpolated into the configuration")
	}
}

// TestAFileReferenceIsNotOpenedDuringValidation covers ADR 0072 section 6.
//
// The config package holds a path. It does not stat it, open it or read it —
// that is the resolver's work, and keeping it there is what lets a configuration
// be validated on a machine that does not have the secrets.
func TestAFileReferenceIsNotOpenedDuringValidation(t *testing.T) {
	cfg, err := load(t, withPassword(
		"      password:\n        file: /nonexistent/definitely/not/here\n"))
	if err != nil {
		t.Fatalf("validation must not require the file to exist: %v", err)
	}
	ref := cfg.Targets[0].Credentials.Password
	if got, want := ref.Kind(), config.SourceFile; got != want {
		t.Errorf("Kind() = %s, want %s", got, want)
	}
	if got, want := ref.Name(), "/nonexistent/definitely/not/here"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

// TestAnEmptyFilePathIsRefused keeps a structurally useless reference out.
func TestAnEmptyFilePathIsRefused(t *testing.T) {
	_, err := load(t, withPassword("      password:\n        file: \"\"\n"))
	assertCategory(t, err, config.CategoryCredentialReference)
}

// TestThereIsNoUsernameIndirection covers ADR 0072 section 11.
//
// A username is identity-classed rather than secret-classed, so it has no
// `{env: ...}` form. Giving it a secret's indirection would suggest it is one.
func TestThereIsNoUsernameIndirection(t *testing.T) {
	_, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: redis\n"+
		"    host: h.example.com\n    credentials:\n      username:\n        env: U\n")
	if err == nil {
		t.Fatal("username accepted a reference form; it is not a secret")
	}
}

// TestThereIsNoStdinCredentialSource covers ADR 0072 section 13.
func TestThereIsNoStdinCredentialSource(t *testing.T) {
	for _, block := range []string{
		"      password:\n        stdin: true\n",
		"      password:\n        exec: /bin/get-secret\n",
		"      password:\n        vault: secret/db\n",
		"      password:\n        value: " + plaintextCanary + "\n",
	} {
		_, err := load(t, withPassword(block))
		if err == nil {
			t.Errorf("an unsupported credential source was accepted: %s", block)
			continue
		}
		if strings.Contains(err.Error(), plaintextCanary) {
			t.Errorf("the refusal echoed a value: %v", err)
		}
	}
}
