package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The credential-source tests.
//
// A secret's bytes cannot be read back out of security.Secret — there is no
// accessor and security.Reveal is confined to wire packages — so these assert on
// what the CLI *does* with the material rather than on the material itself. That
// is the right shape anyway: the property under test is that the bytes reach the
// endpoint unaltered, and the only honest observers of that are emptiness,
// equality against another Secret built the same way, and the endpoint binding.

// writeFile creates a credential file with exact contents.
func writeFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// secretFrom reads through the production path for one source.
func secretFrom(t *testing.T, sources credentialSources, stdin string) (security.Secret, error) {
	t.Helper()
	a := &App{In: strings.NewReader(stdin), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if err := sources.validate(); err != nil {
		return security.Secret{}, err
	}
	return a.readSecret(sources)
}

// TestTrailingLineEndingSemantics is ADR 0049 section 3, byte for byte.
//
// Exactly one trailing "\n" or "\r\n" goes. Everything else — leading spaces,
// trailing spaces, tabs, interior newlines, a *second* trailing newline — is the
// operator's data and survives. TrimSpace would eat most of it and turn a
// correct credential into POSTGRES_CREDENTIALS_REJECTED, which accuses the
// operator's secret store of being wrong.
func TestTrailingLineEndingSemantics(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"bare", "secret", "secret"},
		{"one newline", "secret\n", "secret"},
		{"crlf", "secret\r\n", "secret"},
		{"two newlines keeps one", "secret\n\n", "secret\n"},
		{"three newlines keeps two", "secret\n\n\n", "secret\n\n"},
		{"surrounding spaces survive", " secret ", " secret "},
		{"trailing spaces survive", "secret  ", "secret  "},
		{"trailing spaces then newline", "secret  \n", "secret  "},
		{"leading tab survives", "\tsecret", "\tsecret"},
		{"interior newline survives", "sec\nret", "sec\nret"},
		{"interior newline with trailing", "sec\nret\n", "sec\nret"},
		{"lone carriage return survives", "secret\r", "secret\r"},
		{"crlf then newline", "secret\r\n\n", "secret\r\n"},
		{"only a newline", "\n", ""},
		{"only crlf", "\r\n", ""},
		{"empty", "", ""},
		{"only spaces", "   ", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimOneLineEnding(tt.input); got != tt.want {
				t.Errorf("trimOneLineEnding(%q) = %q, want %q", tt.input, got, tt.want)
			}

			// The same rule through both real sources, observed through the
			// only property a Secret exposes.
			wantEmpty := tt.want == ""
			file, err := secretFrom(t, credentialSources{file: writeFile(t, tt.input)}, "")
			if err != nil {
				t.Fatalf("file source: %v", err)
			}
			if file.IsEmpty() != wantEmpty {
				t.Errorf("file: IsEmpty() = %v, want %v", file.IsEmpty(), wantEmpty)
			}
			stdin, err := secretFrom(t, credentialSources{fromStdin: true}, tt.input)
			if err != nil {
				t.Fatalf("stdin source: %v", err)
			}
			if stdin.IsEmpty() != wantEmpty {
				t.Errorf("stdin: IsEmpty() = %v, want %v", stdin.IsEmpty(), wantEmpty)
			}
		})
	}
}

// TestTrimSpaceIsNotUsed pins the prohibition where it would actually bite.
func TestTrimSpaceIsNotUsed(t *testing.T) {
	const padded = "  pa ss  "
	if got := trimOneLineEnding(padded + "\n"); got != padded {
		t.Errorf("got %q, want %q; TrimSpace would have eaten the padding", got, padded)
	}
	// Code, not comments: secret.go explains at length why TrimSpace is
	// forbidden, and a guard that could not tell the explanation from a call
	// would forbid writing the explanation down.
	if strings.Contains(sourceWithoutComments(t, "secret.go"), "TrimSpace") {
		t.Error("secret.go calls TrimSpace on credential material")
	}
}

// TestTheBoundIsOnTheInputAsRead is ADR 0049's limit, and the edge it implies.
//
// The ADR bounds what is *read* — "Read the file whole, subject to a bounded
// maximum", "Reject input above the bound" — so a 4096-byte secret followed by a
// newline is 4097 bytes of input and is refused, even though the secret it would
// yield sits exactly at the bound. Nothing in the ADR bounds the trimmed secret.
func TestTheBoundIsOnTheInputAsRead(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"one below the bound", strings.Repeat("a", maxCredentialInput-1), false},
		{"exactly the bound", strings.Repeat("a", maxCredentialInput), false},
		{"the bound including its newline", strings.Repeat("a", maxCredentialInput-1) + "\n", false},
		{"the bound plus a newline", strings.Repeat("a", maxCredentialInput) + "\n", true},
		{"one over the bound", strings.Repeat("a", maxCredentialInput+1), true},
		{"far over the bound", strings.Repeat("a", maxCredentialInput*4), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, source := range []string{"file", "stdin"} {
				var err error
				if source == "file" {
					_, err = secretFrom(t, credentialSources{file: writeFile(t, tt.input)}, "")
				} else {
					_, err = secretFrom(t, credentialSources{fromStdin: true}, tt.input)
				}

				if tt.wantErr != (err != nil) {
					t.Errorf("%s: err = %v, wantErr %v", source, err, tt.wantErr)
					continue
				}
				if err == nil {
					continue
				}
				// Oversize is an invocation error, never a truncation.
				if !strings.Contains(err.Error(), "4 KiB") {
					t.Errorf("%s: %q does not name the limit", source, err)
				}
			}
		})
	}
}

// TestOversizeErrorsCarryNoSecretDerivedValue keeps a size out of the message.
//
// A byte count is derived from the secret and buys the reader nothing: the
// actionable fact is that the input was too large, and "8273 bytes" only invites
// the question of what was in it.
func TestOversizeErrorsCarryNoSecretDerivedValue(t *testing.T) {
	const canary = "CANARY-SECRET-VALUE"
	oversize := canary + strings.Repeat("x", maxCredentialInput*2)

	for _, source := range []string{"file", "stdin"} {
		var err error
		if source == "file" {
			_, err = secretFrom(t, credentialSources{file: writeFile(t, oversize)}, "")
		} else {
			_, err = secretFrom(t, credentialSources{fromStdin: true}, oversize)
		}
		if err == nil {
			t.Fatalf("%s: oversize input was accepted", source)
		}
		message := err.Error()
		if strings.Contains(message, canary) {
			t.Errorf("%s: the error carries the credential", source)
		}
		for _, size := range []string{"8192", "8211", "12288", "bytes read"} {
			if strings.Contains(message, size) {
				t.Errorf("%s: the error carries %q, a secret-derived value", source, size)
			}
		}
	}
}

// TestSourcesAreMutuallyExclusive pins the refusal, and that it happens before
// either source is touched.
func TestSourcesAreMutuallyExclusive(t *testing.T) {
	// A path that does not exist, so a fallback would fail loudly, plus stdin
	// material that a "last flag wins" rule would happily use.
	sources := credentialSources{file: "/nonexistent/password", fromStdin: true}
	if err := sources.validate(); err == nil {
		t.Fatal("both sources were accepted")
	}

	_, err := secretFrom(t, sources, "would-have-been-used")
	if err == nil {
		t.Fatal("both sources produced a secret")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want a mutual-exclusion refusal", err)
	}
}

// TestAFailedSourceNeverFallsBackToTheOther is the other half of exclusivity.
//
// An operator who wrote --password-file must not silently authenticate with
// whatever happened to be on stdin.
func TestAFailedSourceNeverFallsBackToTheOther(t *testing.T) {
	_, err := secretFrom(t, credentialSources{file: "/nonexistent/password"},
		"stdin-material-that-must-not-be-used")
	if err == nil {
		t.Fatal("a missing credential file produced a secret")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("err = %v, want a missing-file refusal", err)
	}
}

// TestFileErrorsNameThePathAndNothingElse covers the readable failure modes.
func TestFileErrorsNameThePathAndNothingElse(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing", func(t *testing.T) {
		path := filepath.Join(dir, "absent")
		_, err := secretFrom(t, credentialSources{file: path}, "")
		requirePathOnly(t, err, path, "no such file")
	})

	t.Run("directory", func(t *testing.T) {
		_, err := secretFrom(t, credentialSources{file: dir}, "")
		requirePathOnly(t, err, dir, "directory")
	})

	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root; permission cannot be denied")
		}
		path := filepath.Join(dir, "locked")
		if err := os.WriteFile(path, []byte("secret"), 0o000); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := secretFrom(t, credentialSources{file: path}, "")
		requirePathOnly(t, err, path, "permission denied")
	})
}

func requirePathOnly(t *testing.T, err error, path, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("the source was accepted")
	}
	message := err.Error()
	if !strings.Contains(message, path) {
		t.Errorf("err = %q does not name the path; an operator cannot fix it", message)
	}
	if !strings.Contains(message, reason) {
		t.Errorf("err = %q does not say %q", message, reason)
	}
	if strings.Contains(message, "secret") {
		t.Errorf("err = %q carries the file's contents", message)
	}
}

// TestAnEmptySourceLeavesTheCredentialUnset is the subtle one, and it is why
// credentialFor exists.
//
// security.NewSecret("") is the zero Secret, but security.Credential.IsZero
// reads only the endpoint — so a credential built around an empty secret is not
// zero, and internal/adapter/postgres would walk past its "nothing to present"
// branch and attempt SCRAM with an empty password. An empty source must
// therefore produce no credential at all, which is what makes an empty file, a
// newline-only file and no flag at all reach the same documented outcome.
func TestAnEmptySourceLeavesTheCredentialUnset(t *testing.T) {
	for _, contents := range []string{"", "\n", "\r\n"} {
		secret, err := secretFrom(t, credentialSources{file: writeFile(t, contents)}, "")
		if err != nil {
			t.Fatalf("%q: %v", contents, err)
		}
		if !secret.IsEmpty() {
			t.Errorf("%q produced a non-empty secret", contents)
		}

		credential, err := credentialFor("db.internal", 5432, "app", secret)
		if err != nil {
			t.Fatalf("%q: credentialFor: %v", contents, err)
		}
		if !credential.IsZero() {
			t.Errorf("%q produced a credential; the adapter would then attempt "+
				"authentication with an empty password instead of reporting that "+
				"none was configured", contents)
		}
	}
}

// TestANonEmptySourceBindsToTheLogicalEndpoint pins the other direction.
func TestANonEmptySourceBindsToTheLogicalEndpoint(t *testing.T) {
	secret, err := secretFrom(t, credentialSources{fromStdin: true}, "hunter2\n")
	if err != nil {
		t.Fatalf("readSecret: %v", err)
	}
	credential, err := credentialFor("db.internal", 5432, "app", secret)
	if err != nil {
		t.Fatalf("credentialFor: %v", err)
	}
	if credential.IsZero() {
		t.Fatal("a real secret produced no credential")
	}

	// The credential is authorized by the logical endpoint the operator named,
	// never by an address (ADR 0028 section 2). SecretFor is the only accessor,
	// and it refuses a different endpoint.
	endpoint, err := security.NewEndpoint("db.internal", 5432)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if _, err := credential.SecretFor(endpoint); err != nil {
		t.Errorf("the credential is not bound to the endpoint it was built for: %v", err)
	}
	other, err := security.NewEndpoint("elsewhere.internal", 5432)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if _, err := credential.SecretFor(other); err == nil {
		t.Error("the credential authorized a different endpoint")
	}
}

// TestNoSourceIsAValidRun is the regression that Phase 5.1's product acceptance
// depends on: adding credential support must not make one required.
func TestNoSourceIsAValidRun(t *testing.T) {
	secret, err := secretFrom(t, credentialSources{}, "material-on-stdin-nobody-asked-for")
	if err != nil {
		t.Fatalf("no source should be an error: %v", err)
	}
	if !secret.IsEmpty() {
		t.Error("stdin was read without --password-stdin; source selection must be explicit")
	}
}

// endlessReader never reaches EOF, like /dev/zero or a pipe nobody closes.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// TestTheReadIsBoundedNotJustTheCheck pins the bound on the *read*.
//
// A mutation pass found the gap: replacing io.LimitReader with a plain ReadAll
// left every behavioural test passing, because the size check afterwards still
// refused the result. What changed was invisible to those tests and is the whole
// point of the bound — svcdoctor would consume an unbounded stream into memory
// before deciding it was too large.
//
// The oracle is that the call returns at all. It is run with a generous deadline
// so a slow machine cannot fail it while an unbounded read always does.
func TestTheReadIsBoundedNotJustTheCheck(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := readBoundedSecret(endlessReader{})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an endless stream produced a secret")
		}
		if !strings.Contains(err.Error(), "4 KiB") {
			t.Errorf("err = %v, want the oversize refusal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading an endless stream did not return: the read is unbounded, " +
			"and the size check afterwards cannot save it")
	}
}
