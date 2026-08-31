package secret_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/secret"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Phase 9.1C sections 10 and 11: what happens when the world changes between
// preflight and Resolve, and what the file source does with hostile paths.
//
// # Why a TOCTOU window exists here on purpose
//
// ADR 0072 section 5.2 splits credential handling in two: preflight proves every
// reference resolvable and **retains no value**, and resolution happens per
// target immediately before that target runs. That is a deliberate time-of-check
// / time-of-use gap, and closing it would mean caching secrets — which section 8
// of the same ADR refuses at length, because a cache has to be keyed by the
// reference and a reference is not an authority.
//
// So the gap is not a defect to be fixed; it is a trade chosen with its cost
// stated. What these tests pin is that the *consequences* are truthful:
//
//   - Resolve observes the world as it is at resolution time, never a cached
//     value from preflight.
//   - A source that disappeared produces a local execution failure.
//   - It never produces an authentication finding, because no byte reached any
//     endpoint.
//   - Unrelated targets are unaffected.
//
// A test here that "fixed" TOCTOU by asserting a cached value would be asserting
// the opposite of the contract.

// TestMTE04EnvTOCTOU removes the variable between preflight and Resolve.
func TestMTE04EnvTOCTOU(t *testing.T) {
	t.Setenv("SVCDOCTOR_TOCTOU_ENV", canary)
	cfg := loadOne(t, "env: SVCDOCTOR_TOCTOU_ENV")
	resolver := secret.NewResolver()

	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight with the variable present: %v", err)
	}

	os.Unsetenv("SVCDOCTOR_TOCTOU_ENV")

	_, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err == nil {
		t.Fatal("Resolve succeeded after the variable was removed, so preflight " +
			"retained the value; ADR 0072 section 8 forbids a cache")
	}
	assertResolutionError(t, err, "is not set")
	assertNoCanary(t, err)
}

// TestEnvTOCTOUValueChange proves Resolve reads the *current* value.
//
// The stronger half of the property: a resolver that cached would return the
// preflight value and this would be invisible in the failure case above.
func TestEnvTOCTOUValueChange(t *testing.T) {
	t.Setenv("SVCDOCTOR_TOCTOU_ENV", canary)
	cfg := loadOne(t, "env: SVCDOCTOR_TOCTOU_ENV")
	resolver := secret.NewResolver()

	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	const replacement = "a-different-value-entirely"
	t.Setenv("SVCDOCTOR_TOCTOU_ENV", replacement)

	credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err != nil {
		t.Fatalf("Resolve after the value changed: %v", err)
	}
	assertSecretIs(t, cfg.Targets[0], credential, replacement)
}

// TestMTE04FileTOCTOUDeleted removes the file between preflight and Resolve.
func TestMTE04FileTOCTOUDeleted(t *testing.T) {
	path := writeSecret(t, canary)
	cfg := loadOne(t, "file: "+path)
	resolver := secret.NewResolver()

	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight with the file present: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	_, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err == nil {
		t.Fatal("Resolve succeeded after the file was deleted, so preflight " +
			"retained its contents")
	}
	assertResolutionError(t, err, "no such file")
	assertNoCanary(t, err)
}

// TestFileTOCTOUReplaced replaces the file's contents between the two.
func TestFileTOCTOUReplaced(t *testing.T) {
	path := writeSecret(t, canary)
	cfg := loadOne(t, "file: "+path)
	resolver := secret.NewResolver()

	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	const replacement = "a-completely-different-secret"
	if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
		t.Fatalf("rewriting: %v", err)
	}

	credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err != nil {
		t.Fatalf("Resolve after replacement: %v", err)
	}
	assertSecretIs(t, cfg.Targets[0], credential, replacement)
}

// TestFileTOCTOUBecomesADirectory replaces a regular file with a directory.
//
// The interesting shape: preflight proved "regular file", and by resolution time
// the path is something a read cannot succeed on. It must fail closed rather
// than return whatever a directory read yields.
func TestFileTOCTOUBecomesADirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := loadOne(t, "file: "+path)
	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	if _, err := resolver.CredentialFor(context.Background(), cfg.Targets[0]); err == nil {
		t.Fatal("a path that became a directory resolved successfully")
	}
}

// TestFileTOCTOUPermissionRemoved makes a readable file unreadable.
//
// Skipped for root, which can read anything: asserting a permission refusal as
// root would assert nothing, and a test that silently passes for that reason is
// worse than one that says why it did not run.
func TestFileTOCTOUPermissionRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses the permission bits this asserts")
	}

	path := writeSecret(t, canary)
	cfg := loadOne(t, "file: "+path)
	resolver := secret.NewResolver()

	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
	if err == nil {
		t.Fatal("an unreadable file resolved successfully")
	}
	assertNoCanary(t, err)
}

// TestOneTargetsTOCTOUDoesNotAffectAnother is the isolation half.
//
// Two targets, two references, one of which vanishes. The other must still
// resolve, because credential resolution is per target and nothing is shared.
func TestOneTargetsTOCTOUDoesNotAffectAnother(t *testing.T) {
	t.Setenv("SVCDOCTOR_TOCTOU_KEPT", "kept-secret-value")
	vanishing := writeSecret(t, canary)

	doc := "version: 1\ntargets:\n" +
		"  - id: vanishing\n    type: redis\n    host: a.example.com\n" +
		"    credentials:\n      username: u\n      password:\n        file: " + vanishing + "\n" +
		"  - id: kept\n    type: redis\n    host: b.example.com\n" +
		"    credentials:\n      username: u\n      password:\n        env: SVCDOCTOR_TOCTOU_KEPT\n"

	cfg, err := config.Load([]byte(doc), "c.yaml", registry(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if err := os.Remove(vanishing); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := resolver.CredentialFor(context.Background(), cfg.Targets[0]); err == nil {
		t.Error("the vanished reference resolved")
	}
	credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[1])
	if err != nil {
		t.Fatalf("the unrelated target failed to resolve: %v", err)
	}
	assertSecretIs(t, cfg.Targets[1], credential, "kept-secret-value")
}

// TestSymlinkPolicyIsFollowThenRequireRegular pins the frozen policy exactly.
//
// ADR 0071 section 8.1 and ADR 0072 section 5.1: symlinks are **followed**,
// because a Kubernetes projected volume and a container runtime both deliver a
// secret through one, and refusing them would refuse the documented deployment.
// What must be true is that the destination is a regular file.
func TestSymlinkPolicyIsFollowThenRequireRegular(t *testing.T) {
	dir := t.TempDir()

	t.Run("a symlink to a regular file resolves", func(t *testing.T) {
		target := filepath.Join(dir, "real")
		if err := os.WriteFile(target, []byte(canary), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		cfg := loadOne(t, "file: "+link)
		resolver := secret.NewResolver()
		if err := resolver.PreflightAll(cfg); err != nil {
			t.Fatalf("preflight through a symlink: %v", err)
		}
		credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
		if err != nil {
			t.Fatalf("resolving through a symlink: %v", err)
		}
		assertSecretIs(t, cfg.Targets[0], credential, canary)
	})

	t.Run("a dangling symlink is refused", func(t *testing.T) {
		link := filepath.Join(dir, "dangling")
		if err := os.Symlink(filepath.Join(dir, "absent"), link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		cfg := loadOne(t, "file: "+link)
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "no such file")
	})

	t.Run("a symlink to a directory is refused", func(t *testing.T) {
		link := filepath.Join(dir, "dirlink")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		cfg := loadOne(t, "file: "+link)
		err := secret.NewResolver().PreflightAll(cfg)
		assertResolutionError(t, err, "is a directory")
	})
}

// TestAFIFOIsRefusedWithoutBlocking is the case the regular-file requirement
// exists for.
//
// A FIFO with no writer blocks a reader forever. Preflight uses os.Stat, which
// reads no bytes, so the refusal happens on the file *type* and the process
// never opens it. Without that check a single hostile path in a configuration
// would hang the whole run with no diagnosis and no timeout of its own.
func TestAFIFOIsRefusedWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs")
	}

	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	cfg := loadOne(t, "file: "+path)

	// If this ever blocks, the test times out rather than passing — which is the
	// correct failure for the property being asserted.
	err := secret.NewResolver().PreflightAll(cfg)
	if err == nil {
		t.Fatal("a FIFO was accepted as a credential file")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a FIFO was refused for the wrong reason: %v", err)
	}
}

// TestADeviceFileIsRefused covers the other non-regular type that exists
// everywhere and is safe to read.
//
// /dev/null is chosen deliberately: it is the harmless one. The refusal is on
// the type, so it stands for every device.
func TestADeviceFileIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null")
	}
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("/dev/null is unavailable: %v", err)
	}

	cfg := loadOne(t, "file: /dev/null")
	err := secret.NewResolver().PreflightAll(cfg)
	if err == nil {
		t.Fatal("/dev/null was accepted as a credential file")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a device was refused for the wrong reason: %v", err)
	}
}

// TestFileContentSemanticsAreUnchangedByTheFleetPath is section 11's content
// list, and the point is that it changes nothing.
//
// ADR 0072 section 12 inherits internal/security/secretinput's semantics
// unchanged from ADR 0049 section 3, which the leaf commands already use. A
// fleet-specific tightening here would mean a secret file that works with
// `--password-file` fails in a configuration, which is a difference an operator
// meets while migrating a working invocation into a file.
//
// The one deliberate difference is *preflight*, which the leaf commands have no
// equivalent of, and which is why the empty-file and non-regular cases above are
// refused earlier here than they would be there.
func TestFileContentSemanticsAreUnchangedByTheFleetPath(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"no trailing newline", "s3cret", "s3cret"},
		{"one trailing LF removed", "s3cret\n", "s3cret"},
		{"one trailing CRLF removed", "s3cret\r\n", "s3cret"},
		{"only one line ending removed", "s3cret\n\n", "s3cret\n"},
		{"leading spaces kept", "  s3cret", "  s3cret"},
		{"trailing spaces kept", "s3cret  ", "s3cret  "},
		{"a second line is kept", "s3cret\nmore\n", "s3cret\nmore"},
		{"an embedded NUL is passed through", "s3c\x00ret", "s3c\x00ret"},
		{"a tab is kept", "s3\tcret", "s3\tcret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadOne(t, "file: "+writeSecret(t, tc.content))
			resolver := secret.NewResolver()
			if err := resolver.PreflightAll(cfg); err != nil {
				t.Fatalf("preflight: %v", err)
			}
			credential, err := resolver.CredentialFor(context.Background(), cfg.Targets[0])
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			assertSecretIs(t, cfg.Targets[0], credential, tc.want)
		})
	}
}

// assertSecretIs opens a credential at its own endpoint and compares the value.
//
// # Why this reveals a secret in a test and that is fine
//
// SecretFor is the authority check, and it is being exercised here as well as
// the value: a credential bound to one endpoint cannot be opened at another. The
// reveal itself happens through security.Reveal, which `forbidigo` permits in
// tests and refuses in production outside a wire package — so this file cannot
// be linked into a binary and cannot become a second production call site.
func assertSecretIs(
	t *testing.T, target config.Target, credential security.Credential, want string,
) {
	t.Helper()

	endpoint, err := security.NewEndpoint(target.Host, target.Port)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	plaintext, err := credential.SecretFor(endpoint)
	if err != nil {
		t.Fatalf("SecretFor at the credential's own endpoint: %v", err)
	}
	if got := security.Reveal(plaintext); got != want {
		t.Errorf("resolved %q, want %q", got, want)
	}
}

// assertNoCanary proves an error carries neither the value nor anything derived
// from it, under every formatting verb an error can meet.
func assertNoCanary(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	surfaces := []string{
		err.Error(),
		fmt.Sprintf("%v", err),
		fmt.Sprintf("%+v", err),
		fmt.Sprintf("%#v", err),
		fmt.Sprintf("%q", err),
	}
	// The safe form is the one that may reach a canonical report, so it is held
	// to the same absence as every other surface.
	var resolution *secret.ResolutionError
	if errors.As(err, &resolution) {
		surfaces = append(surfaces, resolution.SafeMessage())
	}
	for _, surface := range surfaces {
		if strings.Contains(surface, canary) {
			t.Errorf("an error surface carries the secret: %q", surface)
		}
	}
}
