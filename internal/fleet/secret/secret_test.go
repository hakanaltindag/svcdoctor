package secret_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/secret"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/redis"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// canary is the value every test in this file plants and then hunts for.
//
// It is deliberately distinctive so that a substring search cannot miss it and
// cannot match by accident, and it is the same value everywhere so that one
// helper can prove absence across every surface.
const canary = "hunter2-CANARY-6f1d9a"

func registry(t *testing.T) *config.Registry {
	t.Helper()
	r, err := config.NewRegistry(redis.Factory{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

// loadOne builds a one-target configuration carrying the given password block.
func loadOne(t *testing.T, password string) config.Config {
	t.Helper()
	doc := "version: 1\ntargets:\n  - id: t\n    type: redis\n    host: h.example.com\n" +
		"    credentials:\n      username: u\n"
	if password != "" {
		doc += "      password:\n        " + password + "\n"
	}
	cfg, err := config.Load([]byte(doc), "c.yaml", registry(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// writeSecret creates a credential file holding value.
func writeSecret(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestEnvResolutionProducesTheSecret is the ordinary env path.
func TestEnvResolutionProducesTheSecret(t *testing.T) {
	t.Setenv("SVCDOCTOR_TEST_PASSWORD", canary)
	cfg := loadOne(t, "env: SVCDOCTOR_TEST_PASSWORD")

	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("PreflightAll: %v", err)
	}

	credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err != nil {
		t.Fatalf("CredentialFor: %v", err)
	}
	if credential.IsZero() {
		t.Fatal("want a bound credential")
	}
	if got, want := credential.Identity(), "u"; got != want {
		t.Errorf("Identity() = %q, want %q", got, want)
	}

	// The credential is bound to the target's own endpoint, and SecretFor is the
	// only way to read it back.
	endpoint, err := security.NewEndpoint("h.example.com", redis.DefaultPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	got, err := credential.SecretFor(endpoint)
	if err != nil {
		t.Fatalf("SecretFor: %v", err)
	}
	if security.Reveal(got) != canary {
		t.Error("the resolved secret is not the environment value")
	}
}

// TestFileResolutionProducesTheSecret is the ordinary file path.
func TestFileResolutionProducesTheSecret(t *testing.T) {
	path := writeSecret(t, canary+"\n")
	cfg := loadOne(t, "file: "+path)

	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("PreflightAll: %v", err)
	}
	credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err != nil {
		t.Fatalf("CredentialFor: %v", err)
	}

	endpoint, err := security.NewEndpoint("h.example.com", redis.DefaultPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	got, err := credential.SecretFor(endpoint)
	if err != nil {
		t.Fatalf("SecretFor: %v", err)
	}
	// Exactly one trailing newline removed, and nothing else — the semantics
	// internal/security/secretinput holds for --password-file too.
	if security.Reveal(got) != canary {
		t.Error("the resolved secret does not match the file's contents")
	}
}

// TestSecretFileSemanticsAreTheLeafCommandsUnchanged is ADR 0072 section 12.
//
// The rules are not restated here; they are exercised. If internal/cli and this
// package ever diverge, one of these cases changes and the other does not.
func TestSecretFileSemanticsAreTheLeafCommandsUnchanged(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"no trailing newline", "abc", "abc"},
		{"one trailing newline", "abc\n", "abc"},
		{"CRLF", "abc\r\n", "abc"},
		{"two newlines keep one", "abc\n\n", "abc\n"},
		{"leading space is kept", " abc", " abc"},
		{"trailing space is kept", "abc ", "abc "},
		{"trailing space before newline is kept", "abc \n", "abc "},
		{"an embedded NUL is passed through", "a\x00b", "a\x00b"},
		{"a second line is part of the secret", "abc\ndef\n", "abc\ndef"},
		{"internal CR is kept", "a\rb", "a\rb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadOne(t, "file: "+writeSecret(t, tt.content))
			credential, err := secret.NewResolver().
				CredentialFor(context.Background(), cfg.Targets[0])
			if err != nil {
				t.Fatalf("CredentialFor: %v", err)
			}
			endpoint, err := security.NewEndpoint("h.example.com", redis.DefaultPort)
			if err != nil {
				t.Fatalf("NewEndpoint: %v", err)
			}
			got, err := credential.SecretFor(endpoint)
			if err != nil {
				t.Fatalf("SecretFor: %v", err)
			}
			if revealed := security.Reveal(got); revealed != tt.want {
				t.Errorf("resolved %q, want %q", revealed, tt.want)
			}
		})
	}
}

// TestPreflightRefusals covers ADR 0072 section 5.1's table.
func TestPreflightRefusals(t *testing.T) {
	dir := t.TempDir()

	t.Run("a missing environment variable", func(t *testing.T) {
		os.Unsetenv("SVCDOCTOR_TEST_ABSENT")
		cfg := loadOne(t, "env: SVCDOCTOR_TEST_ABSENT")
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "is not set")
	})

	t.Run("an empty environment variable", func(t *testing.T) {
		t.Setenv("SVCDOCTOR_TEST_EMPTY", "")
		cfg := loadOne(t, "env: SVCDOCTOR_TEST_EMPTY")
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "set but empty")
	})

	t.Run("a missing file", func(t *testing.T) {
		cfg := loadOne(t, "file: "+filepath.Join(dir, "absent"))
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "no such file")
	})

	t.Run("a directory", func(t *testing.T) {
		cfg := loadOne(t, "file: "+dir)
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "is a directory")
	})

	t.Run("an empty file", func(t *testing.T) {
		cfg := loadOne(t, "file: "+writeSecret(t, ""))
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "is empty")
	})

	t.Run("an oversized file", func(t *testing.T) {
		cfg := loadOne(t, "file: "+writeSecret(t, strings.Repeat("x", 8192)))
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "larger than")
	})

	t.Run("a target with no reference preflights cleanly", func(t *testing.T) {
		cfg := loadOne(t, "")
		if err := secret.NewResolver().PreflightAll(cfg); err != nil {
			t.Fatalf("a target with no credential must preflight: %v", err)
		}
	})
}

// TestANonRegularCredentialFileIsRefusedAtPreflight covers the FIFO case.
func TestANonRegularCredentialFileIsRefusedAtPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := makeFIFO(path); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	cfg := loadOne(t, "file: "+path)
	err := secret.NewResolver().PreflightAll(cfg)
	assertResolutionError(t, err, "not a regular file")
}

// TestPreflightRetainsNoSecretValue is MT-S09.
//
// Preflight's whole purpose is to prove resolvability without residency. The
// configuration is walked afterwards, field by field through reflection, and no
// reachable string may hold the canary.
func TestPreflightRetainsNoSecretValue(t *testing.T) {
	t.Setenv("SVCDOCTOR_TEST_PASSWORD", canary)
	path := writeSecret(t, canary)

	doc := fmt.Sprintf(`
version: 1
targets:
  - id: from-env
    type: redis
    host: a.example.com
    credentials:
      username: u
      password:
        env: SVCDOCTOR_TEST_PASSWORD
  - id: from-file
    type: redis
    host: b.example.com
    credentials:
      username: u
      password:
        file: %s
`, path)

	cfg, err := config.Load([]byte(doc), "c.yaml", registry(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := secret.NewResolver().PreflightAll(cfg); err != nil {
		t.Fatalf("PreflightAll: %v", err)
	}

	if found := findString(reflect.ValueOf(cfg), canary, map[uintptr]bool{}); found != "" {
		t.Errorf("the secret value survived preflight, reachable at %s", found)
	}
}

// TestAValidatedConfigHoldsNoSecretBearingField is the structural half of the
// same claim.
//
// Preflight retaining nothing is a property of the code; a Config having nowhere
// to put a secret is a property of the types, and it is the stronger of the two
// because it also covers code nobody has written yet.
func TestAValidatedConfigHoldsNoSecretBearingField(t *testing.T) {
	forbidden := []reflect.Type{
		reflect.TypeOf(security.Secret{}),
		reflect.TypeOf(security.Credential{}),
	}
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type, string)
	walk = func(t2 reflect.Type, path string) {
		if t2 == nil || seen[t2] {
			return
		}
		seen[t2] = true
		for _, bad := range forbidden {
			if t2 == bad {
				t.Errorf("config.Config reaches %s at %s; a validated configuration must "+
					"hold references and never material", t2, path)
			}
		}
		switch t2.Kind() {
		case reflect.Struct:
			for i := range t2.NumField() {
				field := t2.Field(i)
				walk(field.Type, path+"."+field.Name)
			}
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			walk(t2.Elem(), path+"[]")
		}
	}
	walk(reflect.TypeOf(config.Config{}), "Config")
}

// TestMTS01NoSecretValueReachesAnError is MT-S01 for the resolver.
func TestMTS01NoSecretValueReachesAnError(t *testing.T) {
	// Every failure shape that could plausibly carry a value with it.
	t.Setenv("SVCDOCTOR_TEST_EMPTY", "")
	dir := t.TempDir()

	cases := []struct {
		name     string
		password string
		setup    func(t *testing.T)
	}{
		{"empty env", "env: SVCDOCTOR_TEST_EMPTY", nil},
		{"missing env", "env: SVCDOCTOR_TEST_ABSENT_XYZ", nil},
		{"missing file", "file: " + filepath.Join(dir, "absent"), nil},
		{"directory", "file: " + dir, nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			cfg := loadOne(t, tt.password)
			resolver := secret.NewResolver()

			var messages []string
			if err := resolver.PreflightAll(cfg); err != nil {
				messages = append(messages, err.Error(),
					fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
			}
			if _, err := resolver.CredentialFor(context.Background(), cfg.Targets[0]); err != nil {
				messages = append(messages, err.Error(),
					fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
			}
			if len(messages) == 0 {
				t.Fatal("want a refusal")
			}
			for _, message := range messages {
				if strings.Contains(message, canary) {
					t.Errorf("an error carried the secret value: %s", message)
				}
			}
		})
	}
}

// TestAnOversizedFileRefusalCarriesNoDerivedValue keeps the length out too.
func TestAnOversizedFileRefusalCarriesNoDerivedValue(t *testing.T) {
	const size = 9001
	cfg := loadOne(t, "file: "+writeSecret(t, strings.Repeat("z", size)))
	err := secret.NewResolver().PreflightAll(cfg)
	if err == nil {
		t.Fatal("want an oversize refusal")
	}
	if strings.Contains(err.Error(), fmt.Sprint(size)) {
		t.Errorf("err = %v, want no size derived from the secret", err)
	}
	if strings.Contains(err.Error(), "zzz") {
		t.Errorf("err = %v, want no content", err)
	}
}

// TestMTS05SameReferenceResolvesIndependently is MT-S05 and MT-E10.
//
// Two targets, one variable name, two endpoints. The references are equal; the
// authorities are not, and nothing may conclude the first from the second.
func TestMTS05SameReferenceResolvesIndependently(t *testing.T) {
	t.Setenv("SHARED_PASSWORD", canary)

	cfg, err := config.Load([]byte(`
version: 1
targets:
  - id: orders-db
    type: redis
    host: orders.example.com
    credentials:
      username: u
      password:
        env: SHARED_PASSWORD
  - id: billing-db
    type: redis
    host: billing.example.com
    credentials:
      username: u
      password:
        env: SHARED_PASSWORD
`), "c.yaml", registry(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resolver := secret.NewResolver()
	first, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err != nil {
		t.Fatalf("CredentialFor(0): %v", err)
	}
	second, err := resolver.CredentialFor(context.Background(), cfg.Targets[1])
	if err != nil {
		t.Fatalf("CredentialFor(1): %v", err)
	}

	// Each is bound to its own endpoint...
	if first.Endpoint().Equal(second.Endpoint()) {
		t.Fatal("two targets on different hosts produced one endpoint")
	}
	// ...and neither can be used at the other's.
	if _, err := first.SecretFor(second.Endpoint()); !errors.Is(err, security.ErrEndpointMismatch) {
		t.Errorf("target A's credential was usable at target B's endpoint: %v", err)
	}
	if _, err := second.SecretFor(first.Endpoint()); !errors.Is(err, security.ErrEndpointMismatch) {
		t.Errorf("target B's credential was usable at target A's endpoint: %v", err)
	}
}

// TestResolutionReadsTheSourceEveryTime is MT-S04's behavioural half.
//
// No cache means a changed source produces a changed secret. A cache — of any
// kind, keyed any way — would return the first value and fail this.
func TestResolutionReadsTheSourceEveryTime(t *testing.T) {
	path := writeSecret(t, "first-value")
	cfg := loadOne(t, "file: "+path)
	resolver := secret.NewResolver()
	endpoint, err := security.NewEndpoint("h.example.com", redis.DefaultPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}

	reveal := func() string {
		t.Helper()
		credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
		if err != nil {
			t.Fatalf("CredentialFor: %v", err)
		}
		got, err := credential.SecretFor(endpoint)
		if err != nil {
			t.Fatalf("SecretFor: %v", err)
		}
		return security.Reveal(got)
	}

	if got := reveal(); got != "first-value" {
		t.Fatalf("first resolution = %q", got)
	}
	if err := os.WriteFile(path, []byte("second-value"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := reveal(); got != "second-value" {
		t.Errorf("second resolution = %q, want %q; a cached secret would return the first",
			got, "second-value")
	}
}

// TestEnvResolutionReadsTheEnvironmentEveryTime is the same claim for env.
func TestEnvResolutionReadsTheEnvironmentEveryTime(t *testing.T) {
	t.Setenv("SVCDOCTOR_TEST_ROTATING", "before")
	cfg := loadOne(t, "env: SVCDOCTOR_TEST_ROTATING")
	resolver := secret.NewResolver()

	first, err := resolver.Resolve(context.Background(), cfg.Targets[0].Credentials.Password)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	t.Setenv("SVCDOCTOR_TEST_ROTATING", "after")
	second, err := resolver.Resolve(context.Background(), cfg.Targets[0].Credentials.Password)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if security.Reveal(first) != "before" || security.Reveal(second) != "after" {
		t.Error("resolution did not read the environment on every call")
	}
}

// TestAnEmptyResolvedCredentialIsARefusal covers the written-but-empty case.
func TestAnEmptyResolvedCredentialIsARefusal(t *testing.T) {
	// A file holding only a newline trims to nothing. The leaf command maps that
	// to "no credential"; a written fleet reference asked for one, so it is a
	// resolution failure rather than a silent unset (ADR 0072 §5.1).
	cfg := loadOne(t, "file: "+writeSecret(t, "\n"))
	_, err := secret.NewResolver().CredentialFor(context.Background(), cfg.Targets[0])
	assertResolutionError(t, err, "empty credential")
}

// TestNoReferenceProducesNoCredential is the supported no-credential run.
func TestNoReferenceProducesNoCredential(t *testing.T) {
	cfg := loadOne(t, "")
	credential, err := secret.NewResolver().CredentialFor(context.Background(), cfg.Targets[0])
	if err != nil {
		t.Fatalf("a target with no credential must not be an error: %v", err)
	}
	if !credential.IsZero() {
		t.Error("want the zero credential")
	}
}

// TestResolveRefusesACancelledContext keeps a cancelled run from touching a secret.
func TestResolveRefusesACancelledContext(t *testing.T) {
	t.Setenv("SVCDOCTOR_TEST_PASSWORD", canary)
	cfg := loadOne(t, "env: SVCDOCTOR_TEST_PASSWORD")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := secret.NewResolver().Resolve(ctx, cfg.Targets[0].Credentials.Password)
	if !errors.Is(err, secret.ErrResolution) {
		t.Errorf("err = %v, want a resolution refusal on a cancelled context", err)
	}
}

// TestReferenceFormattingCannotLeak is MT-S01's type-level half.
func TestReferenceFormattingCannotLeak(t *testing.T) {
	t.Setenv("SVCDOCTOR_TEST_PASSWORD", canary)
	cfg := loadOne(t, "env: SVCDOCTOR_TEST_PASSWORD")
	ref := cfg.Targets[0].Credentials.Password

	for _, rendered := range []string{
		ref.String(),
		fmt.Sprintf("%v", ref),
		fmt.Sprintf("%+v", ref),
		fmt.Sprintf("%#v", ref),
		//nolint:staticcheck // S1025: exercising the %s verb is the point. A Stringer
		// that leaked under one verb and not another is exactly what this hunts.
		fmt.Sprintf("%s", ref),
		fmt.Sprintf("%v", cfg),
		fmt.Sprintf("%+v", cfg),
	} {
		if strings.Contains(rendered, canary) {
			t.Errorf("a rendering carried the secret: %s", rendered)
		}
	}
	// The name is expected to appear: it is what an operator needs to fix it.
	if !strings.Contains(ref.String(), "SVCDOCTOR_TEST_PASSWORD") {
		t.Errorf("String() = %q, want the reference name", ref.String())
	}
}

func assertResolutionError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want a resolution refusal containing %q, got no error", want)
	}
	if !errors.Is(err, secret.ErrResolution) {
		t.Fatalf("err = %v, want it to match secret.ErrResolution", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to contain %q", err, want)
	}
}

// findString reports a reachable field path holding want, or "".
//
// It walks exported and unexported fields alike through reflection, because a
// secret retained in an unexported field would be exactly as leaked and exactly
// as invisible to a test that only read the API.
func findString(v reflect.Value, want string, seen map[uintptr]bool) string {
	switch v.Kind() {
	case reflect.String:
		if strings.Contains(v.String(), want) {
			return "<string>"
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if found := findString(v.Field(i), want, seen); found != "" {
				return "." + v.Type().Field(i).Name + found
			}
		}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return ""
		}
		if v.Kind() == reflect.Pointer {
			if seen[v.Pointer()] {
				return ""
			}
			seen[v.Pointer()] = true
		}
		if found := findString(v.Elem(), want, seen); found != "" {
			return "*" + found
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if found := findString(v.Index(i), want, seen); found != "" {
				return fmt.Sprintf("[%d]%s", i, found)
			}
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			if found := findString(v.MapIndex(key), want, seen); found != "" {
				return fmt.Sprintf("[%v]%s", key, found)
			}
		}
	}
	return ""
}

// TestTheSafeMessageNamesNoReference is ADR 0074 section 4.2, on the real type.
//
// # Why this exists separately from the scheduler's test
//
// internal/fleet/run proves that the scheduler *asks for* the safe form, using a
// fake error. Nothing proved that the real ResolutionError's safe form is
// actually safe — so mutations B21 and B23, which made SafeMessage return the
// full text and the file path, both survived the whole Phase 9.1B matrix.
//
// The two halves are genuinely separate: one is about which method the scheduler
// calls, the other about what that method returns. A single test cannot cover
// both without the fake becoming the real thing.
func TestTheSafeMessageNamesNoReference(t *testing.T) {
	const envName = "VERY_DISTINCTIVE_VARIABLE_NAME"
	filePath := writeSecret(t, "")

	tests := []struct {
		name      string
		password  string
		reference string
	}{
		{"env", "env: " + envName, envName},
		{"file", "file: " + filePath, filePath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(envName)
			cfg := loadOne(t, tt.password)

			err := secret.NewResolver().PreflightAll(cfg)
			if err == nil {
				t.Fatal("want a refusal")
			}

			var resolution *secret.ResolutionError
			if !errors.As(err, &resolution) {
				t.Fatalf("err = %T, want a *secret.ResolutionError", err)
			}

			// Error names the reference: that message is for stderr, and an
			// operator cannot fix what svcdoctor will not name.
			if !strings.Contains(resolution.Error(), tt.reference) {
				t.Errorf("Error() = %q, want it to name %q so the operator can fix it",
					resolution.Error(), tt.reference)
			}

			// SafeMessage does not: that message is for the canonical report,
			// which is attached to tickets and pasted into chats.
			safe := resolution.SafeMessage()
			if strings.Contains(safe, tt.reference) {
				t.Errorf("SafeMessage() = %q, which names the credential reference. "+
					"ADR 0074 §4.2 keeps a reference name, a file path and an environment "+
					"variable name out of the report entirely.", safe)
			}
			if safe == "" {
				t.Error("SafeMessage() is empty; a reader still needs to know what happened")
			}
			// The source kind survives, because it is a property of the
			// configuration's shape rather than of any deployment, and it tells a
			// reader which half of the file to look at.
			if !strings.Contains(safe, tt.name) {
				t.Errorf("SafeMessage() = %q, want it to name the source kind %q",
					safe, tt.name)
			}
		})
	}
}

// TestTheSafeMessageIsAlsoSafeUnderEveryFormattingVerb closes the other route.
func TestTheSafeMessageIsAlsoSafeUnderEveryFormattingVerb(t *testing.T) {
	const envName = "ANOTHER_DISTINCTIVE_NAME"
	os.Unsetenv(envName)

	err := secret.NewResolver().PreflightAll(loadOne(t, "env: "+envName))
	if err == nil {
		t.Fatal("want a refusal")
	}
	var resolution *secret.ResolutionError
	if !errors.As(err, &resolution) {
		t.Fatalf("err = %T, want a *secret.ResolutionError", err)
	}

	// %#v must not print the struct field by field, which would reveal the name
	// a GoString exists to withhold.
	if strings.Contains(fmt.Sprintf("%#v", resolution), envName) {
		t.Errorf("%%#v = %q, which names the reference", fmt.Sprintf("%#v", resolution))
	}
}
