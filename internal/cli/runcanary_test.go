package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The Phase 9.1C adversarial secret corpus, MT-S01 through MT-S04 at width.
//
// # What this adds over the single-canary test beside it
//
// TestMTS01ToS04NoSecretReachesAnyRunSurface plants one well-behaved ASCII value
// and hunts for it. That proves the *plumbing* is right, and it is the test that
// would catch a report field carrying a password. It cannot catch a redaction
// that is defeated by the shape of the value itself.
//
// So this plants values chosen to break naive containment: text that survives
// JSON escaping differently from how it was written, text that a formatting verb
// would mangle, text that collides with the username, the hostname, the target
// identifier or the environment variable name, and text long enough that a
// truncating writer would emit a prefix of it.
//
// # Absence is asserted in three representations, not one
//
// A secret containing a newline is written into JSON as `\n`, so searching the
// JSON document for the raw value finds nothing while the secret is sitting
// there in plain sight. The same applies to a backslash, a quote and a tab. Each
// surface is therefore searched for the raw value, for its JSON-escaped form and
// for its newline-normalized form.

// canarySecret is one adversarial value and the reason it is adversarial.
type canarySecret struct {
	name  string
	value string
}

// adversarialSecrets is the Phase 9.1C section 6 list.
//
// `username`, `hostname`, `targetID` and `envName` below are the fixed values
// the configuration uses, so the prefix- and suffix-sharing cases can collide
// with them deliberately.
func adversarialSecrets() []canarySecret {
	const (
		username = "svcdoctor"
		hostname = "canary-target.invalid"
		targetID = "canary-one"
		envName  = "SVCDOCTOR_CANARY_PASSWORD"
	)

	return []canarySecret{
		{"ordinary ascii", "hunter2CanaryPlain"},
		{"internal spaces", "hunter 2 canary value"},
		{"leading and trailing spaces", "  hunter2CanarySpaced  "},
		{"double quotes", `hunter2"canary"quoted`},
		{"single quotes", "hunter2'canary'quoted"},
		{"backslashes", `hunter2\canary\\escaped`},
		{"newline", "hunter2\ncanary\nlines"},
		{"CRLF", "hunter2\r\ncanary\r\nlines"},
		{"tabs", "hunter2\tcanary\ttabbed"},
		{"JSON-looking", `{"password":"hunter2CanaryJSON"}`},
		{"YAML-looking", "password: hunter2CanaryYAML\nenv: X"},
		{"shell-looking", "$(cat /etc/passwd) && hunter2CanaryShell"},
		{"percent s", "%s-hunter2CanaryVerb"},
		{"percent plus v", "%+v-hunter2CanaryVerb"},
		{"percent q", "%q-hunter2CanaryVerb"},
		{"percent hash v", "%#v-hunter2CanaryVerb"},
		{"unicode", "hünter2Ϝαναρυ日本語"},
		{"emoji", "hunter2🔐🙈canary"},
		{"very long", strings.Repeat("hunter2CanaryLong", 100)},
		{"prefix shared with username", username + "-hunter2CanaryPrefix"},
		{"suffix shared with username", "hunter2CanarySuffix-" + username},
		{"prefix shared with hostname", hostname + "-hunter2CanaryHost"},
		{"suffix shared with hostname", "hunter2CanaryHost-" + hostname},
		{"equal to the environment variable name", envName},
		{"equal to a file path fragment", "/run/secrets/hunter2CanaryPath"},
	}
}

// reportedValueSecrets are the two cases whose expected outcome is different,
// and they are separated rather than dropped.
//
// A secret set *equal to a value the report is required to carry* cannot be
// hidden by any redaction: the report names the target the operator asked about
// and the identity svcdoctor connected as, and if the password happens to equal
// one of those, the characters are on the page either way. Asserting absence
// there would be asserting that svcdoctor stops reporting the target ID.
//
// TestASecretEqualToAReportedValueIsIndistinguishable pins the honest property
// instead: the appearance is caused by the *reported value*, not by the secret,
// which it proves by changing the secret and getting identical output.
func reportedValueSecrets() []canarySecret {
	return []canarySecret{
		{"equal to the target id", "canary-one"},
		{"equal to the username", "svcdoctor"},
	}
}

// canaryConfig builds a run in which the same secret reaches two targets by two
// different sources, so both resolver paths are covered by every value.
//
// The endpoints are `.invalid`, which RFC 2606 guarantees never resolves. Every
// target therefore fails at DNS, quickly and with no network reachable — the
// point is what the *report* carries, not what an endpoint said.
func canaryConfig(t *testing.T, secretPath string) string {
	t.Helper()
	return writeConfig(t, fmt.Sprintf(`
version: 1
run:
  concurrency: 2
targets:
  - id: canary-one
    type: redis
    host: canary-target.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    credentials:
      username: svcdoctor
      password:
        env: SVCDOCTOR_CANARY_PASSWORD
  - id: canary-two
    type: postgres
    host: canary-target.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    credentials:
      username: svcdoctor
      password:
        file: %s
    config:
      database: canary
`, secretPath))
}

// representations returns the forms a value can legitimately take on a surface.
//
// Searching only for the raw bytes is the mistake this exists to avoid: a secret
// containing a newline appears in JSON as `\n` and in no other form, so a search
// for the raw value finds nothing while the value is fully present.
func representations(value string) map[string]string {
	forms := map[string]string{"raw": value}

	if encoded, err := json.Marshal(value); err == nil {
		// Trim the surrounding quotes: the interesting part is the escaped body,
		// which is what would sit inside a JSON string field.
		if body := string(encoded); len(body) >= 2 {
			forms["json-escaped"] = body[1 : len(body)-1]
		}
	}
	forms["quoted"] = strconv.Quote(value)

	normalized := strings.ReplaceAll(value, "\r\n", "\n")
	if normalized != value {
		forms["newline-normalized"] = normalized
	}
	return forms
}

// searchable reports whether a form is distinctive enough to search for.
//
// A one-character form, or one made only of punctuation, collides with ordinary
// report text and would make the assertion fire on prose rather than on a leak.
// Excluding it is stated rather than silent, because it is the one place this
// corpus is weaker than it looks.
func searchable(form string) bool {
	if len(form) < 6 {
		return false
	}
	for _, r := range form {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127 {
			return true
		}
	}
	return false
}

// TestMTS01ToS04TheAdversarialSecretCorpusNeverEscapes is the corpus itself.
func TestMTS01ToS04TheAdversarialSecretCorpusNeverEscapes(t *testing.T) {
	for _, secret := range adversarialSecrets() {
		t.Run(secret.name, func(t *testing.T) {
			t.Setenv("SVCDOCTOR_CANARY_PASSWORD", secret.value)
			path := canaryConfig(t, writeSecretFile(t, secret.value))

			for _, args := range [][]string{
				{"run", "--config", path},
				{"run", "--config", path, "--output", "json"},
				{"run", "--config", path, "--shareable"},
				{"run", "--config", path, "--output", "json", "--shareable"},
			} {
				mode := strings.Join(args[3:], " ")
				if mode == "" {
					mode = "terminal"
				}

				var stdout, stderr bytes.Buffer
				newTestApp(&stdout, &stderr).Run(context.Background(), args)

				if stdout.Len() == 0 {
					t.Fatalf("%s produced no output; the case would pass vacuously", mode)
				}
				assertAbsent(t, mode+" stdout", stdout.String(), secret.value)
				assertAbsent(t, mode+" stderr", stderr.String(), secret.value)
			}
		})
	}
}

// assertAbsent hunts for every representation of value in surface.
func assertAbsent(t *testing.T, where, surface, value string) {
	t.Helper()
	for form, text := range representations(value) {
		if !searchable(text) {
			continue
		}
		if strings.Contains(surface, text) {
			t.Errorf("the %s form of the secret appeared on %s", form, where)
		}
	}
}

// TestTheCanaryCorpusWouldCatchALeak proves the corpus is not vacuous.
//
// Every case above asserts an absence, and an absence test that cannot fail is
// worth nothing. This feeds each adversarial value through the same search
// against a surface that genuinely contains it, and requires a hit.
//
// It is also where the `searchable` exclusion is held honest: a value that this
// test cannot find is one the corpus above could never have caught either.
func TestTheCanaryCorpusWouldCatchALeak(t *testing.T) {
	for _, secret := range adversarialSecrets() {
		t.Run(secret.name, func(t *testing.T) {
			for form, text := range representations(secret.value) {
				if !searchable(text) {
					continue
				}
				leaky := "prefix " + text + " suffix"
				probe := &testing.T{}
				assertAbsent(probe, "a surface holding it", leaky, secret.value)
				if !probe.Failed() {
					t.Errorf("the %s form is not detectable, so the corpus could not "+
						"catch a leak of it", form)
				}
			}
		})
	}
}

// TestMTS11AndS12NoCredentialSourceMetadataReachesTheAggregate is section 7.
//
// The environment variable name, the credential file path and the configuration
// file path are each written into the run and each must be absent from both
// canonical forms. They are not secrets, and that is exactly why they are easy
// to serialize by accident: ADR 0074 section 4.2 keeps them out because a report
// is the artifact most likely to be pasted somewhere public, and a variable name
// plus a file path is a map of where the secrets live.
func TestMTS11AndS12NoCredentialSourceMetadataReachesTheAggregate(t *testing.T) {
	const value = "hunter2CanaryMetadata"
	t.Setenv("SVCDOCTOR_CANARY_PASSWORD", value)

	secretPath := writeSecretFile(t, value)
	configPath := canaryConfig(t, secretPath)

	forbidden := map[string]string{
		"the environment variable name": "SVCDOCTOR_CANARY_PASSWORD",
		"the credential file path":      secretPath,
		"the configuration file path":   configPath,
		"a Go reference type name":      "SecretRef",
		"the reference struct name":     "config.Reference",
		"the source kind type name":     "SourceKind",
	}

	for _, args := range [][]string{
		{"run", "--config", configPath, "--output", "json"},
		{"run", "--config", configPath, "--output", "json", "--shareable"},
		{"run", "--config", configPath},
		{"run", "--config", configPath, "--shareable"},
	} {
		t.Run(strings.Join(args[3:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			newTestApp(&stdout, &stderr).Run(context.Background(), args)

			out := stdout.String()
			if out == "" {
				t.Fatal("no aggregate was produced; this case would pass vacuously")
			}
			for what, text := range forbidden {
				if strings.Contains(out, text) {
					t.Errorf("%s reached the canonical aggregate", what)
				}
			}
			_ = stderr
		})
	}
}

// TestSourceMetadataIsStillNameableOnStderr is the other half of ADR 0072
// section 10's split, and it is asserted so that the test above cannot be
// satisfied by removing the diagnostic entirely.
//
// An operator whose environment variable is missing has to be told *which*
// variable. That message is ephemeral, local, and read by the person who owns
// the file — a different surface with a different audience from the report.
func TestSourceMetadataIsStillNameableOnStderr(t *testing.T) {
	os.Unsetenv("SVCDOCTOR_CANARY_PASSWORD")
	path := canaryConfig(t, writeSecretFile(t, "hunter2CanaryStderr"))

	var stdout, stderr bytes.Buffer
	newTestApp(&stdout, &stderr).Run(context.Background(), []string{"run", "--config", path})

	if !strings.Contains(stderr.String(), "SVCDOCTOR_CANARY_PASSWORD") {
		t.Errorf("stderr does not name the missing variable, so an operator cannot "+
			"fix it: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("a preflight refusal wrote %d bytes to stdout; no report exists",
			stdout.Len())
	}
}

// TestASecretEqualToAReportedValueIsIndistinguishable states a real limit of
// redaction, and proves svcdoctor is not the cause of it.
//
// # The limit
//
// A report names the target the operator asked about and the identity svcdoctor
// authenticated as. If an operator's password *is* their username, those
// characters appear in the report because the username appears in the report.
// No structural redaction can resolve that: the two values are the same value,
// and the document's purpose requires printing one of them.
//
// svcdoctor makes no claim to the contrary, and this test exists so that the
// claim is never made by accident — a future reader who finds the corpus above
// silent on these two cases would reasonably assume they were covered.
//
// # What is actually asserted
//
// That the output does not depend on the secret. The same run is performed twice
// with two different passwords, and the two documents must be byte-identical
// once the run's own timing is normalized. If a secret were reaching the report,
// changing it would change the bytes.
func TestASecretEqualToAReportedValueIsIndistinguishable(t *testing.T) {
	for _, secret := range reportedValueSecrets() {
		t.Run(secret.name, func(t *testing.T) {
			render := func(password string) string {
				t.Setenv("SVCDOCTOR_CANARY_PASSWORD", password)
				path := canaryConfig(t, writeSecretFile(t, password))

				var stdout, stderr bytes.Buffer
				newTestApp(&stdout, &stderr).Run(context.Background(),
					[]string{"run", "--config", path, "--output", "json"})
				if stdout.Len() == 0 {
					t.Fatal("no aggregate was produced")
				}
				return normalizeRunTiming(t, stdout.String())
			}

			collidingSecret := render(secret.value)
			unrelatedSecret := render("an-entirely-different-hunter2Value")

			if collidingSecret != unrelatedSecret {
				t.Error("the aggregate changed when only the password changed, so " +
					"something about the secret is reaching the report")
			}
			if !strings.Contains(collidingSecret, secret.value) {
				t.Fatalf("%q is not in the report at all, so this case proves "+
					"nothing", secret.value)
			}
		})
	}
}

// normalizeRunTiming removes the two fields that legitimately differ between two
// runs, so everything else can be compared exactly.
func normalizeRunTiming(t *testing.T, document string) string {
	t.Helper()

	var parsed map[string]any
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("the aggregate is not valid JSON: %v", err)
	}
	stripTiming(parsed)

	normalized, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	return string(normalized)
}

// stripTiming walks the document and blanks every measured time value.
func stripTiming(node any) {
	switch value := node.(type) {
	case map[string]any:
		for key := range value {
			switch key {
			case "startedAt", "duration", "elapsed", "finishedAt", "at":
				value[key] = "<normalized>"
			default:
				stripTiming(value[key])
			}
		}
	case []any:
		for _, item := range value {
			stripTiming(item)
		}
	}
}
