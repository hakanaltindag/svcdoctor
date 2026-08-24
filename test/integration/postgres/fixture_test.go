//go:build integration

package postgres

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The fixture's own contract.
//
// # Why this test exists
//
// The v0.3.1 release failed here, on a GitHub Linux runner, after passing on
// every developer machine. There are three ways for PostgreSQL to refuse its
// TLS private key: two of its own checks, and the operating system, which it
// reports with a different message. Measured against `postgres:18` on a
// Linux-native filesystem, where `postgres` is uid 999:
//
//	owner              mode   result
//	1001:1001 (host)   0600   FATAL: must be owned by the database user or root
//	999:999            0600   starts
//	999:999            0400   starts
//	999:999            0640   FATAL: has group or world access
//	0:0    (root)      0600   FATAL: could not load ...: Permission denied
//	0:0    (root)      0640   FATAL: could not load ...: Permission denied
//	0:999              0640   starts
//
// `gen-certs.sh` set the mode and not the owner.
//
// # Why root ownership is refused here even though PostgreSQL allows it
//
// PostgreSQL's ownership check accepts the database user or root. The server
// process, however, runs as `postgres`, so a root-owned key only opens when the
// group is `postgres` and group-read is set — `0:0` at any mode fails at
// `open()` after passing both checks.
//
// And `0:0` is not a hypothetical. It is what macOS Docker Desktop reports for
// an un-chowned host key. Measured, pre-fix, with the host file owned by the
// developer (501):
//
//	host view:       uid=501 gid=0  mode=600
//	container view:  uid=0   gid=0  mode=600
//	result:          starts
//
// The mount layer reports the file as root-owned and grants the read anyway, so
// both checks pass on a value the host never had. That is the whole reason this
// reached a release tag — and it means a guard that accepts a root-owned key
// accepts the broken state verbatim on the one machine a developer runs. So
// these tests require exactly what the fixture produces: owned by the database
// user, mode 0600, the only configuration that is both minimal and correct.
//
// # Why it asserts on files rather than on the script
//
// A test that greps `gen-certs.sh` for `chown` proves the script contains a
// word. The property that matters is what the *container* sees when it opens
// the file, and the whole defect was a gap between what the script said and
// what the filesystem delivered — the old script even carried a comment
// describing the ownership requirement it did not implement.
//
// So these read the real files through a container, the same way PostgreSQL
// does. They run under the `integration` tag, which means they run on the Linux
// CI where the difference is real, not only where it is invisible.

// fixtureEnv is the directory holding the generated certificates.
func fixtureEnv(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("env")
	if err != nil {
		t.Fatalf("resolving the fixture directory: %v", err)
	}
	return dir
}

// postgresImage reads the image from the compose file, so this test cannot
// disagree with what actually runs.
func postgresImage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureEnv(t), "compose.yaml"))
	if err != nil {
		t.Fatalf("reading compose.yaml: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "image:") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
		}
	}
	t.Fatal("compose.yaml declares no image")
	return ""
}

// inContainer runs a shell command inside the pinned PostgreSQL image with the
// certificate directory mounted, and returns its output. Reading the files the
// way the server does is the point: a host-side os.Stat on macOS reports
// something the container never sees.
func inContainer(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.Command("docker", "run", "--rm",
		"-v", fixtureEnv(t)+"/certs:/c:ro",
		postgresImage(t), "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inspecting the fixture certificates: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestTheTLSKeyIsOwnedByTheDatabaseUser pins the condition that failed v0.3.1.
func TestTheTLSKeyIsOwnedByTheDatabaseUser(t *testing.T) {
	fields := strings.Fields(inContainer(t,
		`stat -c "%u %g %a" /c/server.key; id -u postgres; id -g postgres`))
	if len(fields) != 5 {
		t.Fatalf("unexpected inspection output: %q", fields)
	}
	keyUID, keyGID, mode := fields[0], fields[1], fields[2]
	pgUID, pgGID := fields[3], fields[4]

	t.Logf("server.key uid=%s gid=%s mode=%s; postgres uid=%s gid=%s",
		keyUID, keyGID, mode, pgUID, pgGID)

	// The database user, and not root. See the file comment: root passes
	// PostgreSQL's own check and then fails at open(), and `0:0` is exactly what
	// macOS reports for the unfixed state, so accepting it would make this test
	// pass on the broken fixture.
	if keyUID != pgUID {
		detail := ""
		if keyUID == "0" {
			detail = "\n\nuid 0 is what a macOS bind mount reports for a key that was " +
				"never chowned, and a root-owned key cannot be opened by the server " +
				"process on Linux. It is the unfixed state, not an alternative to it."
		}
		t.Errorf("server.key is owned by uid %s, not the database user (uid %s).%s\n\n"+
			"This is the condition that failed the v0.3.1 release: the key was owned "+
			"by the CI runner's uid, PostgreSQL refused to start, and the readiness "+
			"loop timed out reporting only that the server was not ready.",
			keyUID, pgUID, detail)
	}
	if keyGID != pgGID {
		t.Errorf("server.key has group %s, not the postgres group (%s)", keyGID, pgGID)
	}
}

// TestTheTLSKeyIsNotGroupOrWorldReadable pins the second of PostgreSQL's
// checks. Broadening the mode is the tempting wrong fix for an ownership
// problem, and it produces a different fatal error rather than a working server.
func TestTheTLSKeyIsNotGroupOrWorldReadable(t *testing.T) {
	out := inContainer(t, `stat -c "%a" /c/server.key`)
	perm, err := strconv.ParseInt(strings.TrimSpace(out), 8, 32)
	if err != nil {
		t.Fatalf("parsing mode %q: %v", out, err)
	}

	// A key owned by the database user may carry no group or world bits at all:
	// PostgreSQL rejects 0640 with "has group or world access", measured. The
	// owner test above is what establishes that this is the applicable rule.
	if perm&^int64(0o600) != 0 {
		t.Errorf("server.key mode is %04o; a key owned by the database user may "+
			"carry no group or world bits, and PostgreSQL rejects 0640 and above "+
			"with \"has group or world access\".", perm)
	}
	if perm&0o044 != 0 {
		t.Errorf("server.key is group- or world-readable (mode %04o)", perm)
	}
}

// TestTheCertificateIsReadableByTheServer guards the opposite mistake: locking
// the public certificate down so far that the server cannot read it. It is
// public material and only the key needs protecting.
func TestTheCertificateIsReadableByTheServer(t *testing.T) {
	out := inContainer(t, `stat -c "%u %a" /c/server.crt; id -u postgres`)
	fields := strings.Fields(out)
	if len(fields) != 3 {
		t.Fatalf("unexpected inspection output: %q", out)
	}
	crtUID, mode, pgUID := fields[0], fields[1], fields[2]
	perm, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		t.Fatalf("parsing mode %q: %v", mode, err)
	}
	readable := crtUID == pgUID && perm&0o400 != 0
	readable = readable || perm&0o004 != 0
	if !readable {
		t.Errorf("server.crt (uid %s, mode %04o) is not readable by postgres (uid %s)",
			crtUID, perm, pgUID)
	}
}

// TestNoKeyMaterialIsCommitted pins the habit, not just this fixture. A
// repository that ships a private key teaches the wrong lesson even when the
// key is worthless.
func TestNoKeyMaterialIsCommitted(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "--", "test/integration")
	cmd.Dir = repoRootFromFixture(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("git is unavailable: %v", err)
	}
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch strings.ToLower(filepath.Ext(f)) {
		case ".key", ".p12", ".pfx":
			t.Errorf("%s is tracked; fixture key material must never be committed", f)
		case ".pem":
			if strings.Contains(strings.ToLower(f), "key") {
				t.Errorf("%s is tracked; fixture key material must never be committed", f)
			}
		}
	}
}

// repoRootFromFixture walks up to the module root.
func repoRootFromFixture(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving the working directory: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root")
	return ""
}
