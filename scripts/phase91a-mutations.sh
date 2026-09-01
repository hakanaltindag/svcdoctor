#!/usr/bin/env bash
# Phase 9.1A mutation closure.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is then restored and verified byte-for-byte against a checksum
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it, because a mutation run that leaves
# residue is worse than one that was never performed.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/fleet/config/document.go
  internal/fleet/config/credential.go
  internal/fleet/config/load.go
  internal/fleet/config/schema.go
  internal/fleet/config/node.go
  internal/fleet/config/target.go
  internal/fleet/config/registry.go
  internal/fleet/secret/secret.go
  internal/fleet/services/redis/redis.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"

restore() {
  for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done
}

PASS=0
FAIL=0
SURVIVORS=()

# mutate <id> <description> <file> <python-replacement-script> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  # A -run regex that selects **no test** makes `go test` exit 0, which this
  # harness would read as a survivor. That is exactly how twenty mutations across
  # phase91a and phase91b sat "surviving" from Phase 9.1C — which renamed 28 test
  # functions — until the v0.4.0 release gate measured them: every one was caught
  # by its package's full suite, and only the narrow regex had gone stale.
  #
  # An empty selection is a harness failure rather than a finding about the
  # product; the two need opposite fixes and look identical without this.
  #
  # Checked on the **pristine** tree, before planting. After planting, a mutation
  # that deliberately breaks the build produces no `=== RUN` either, and a check
  # placed later cannot tell "the regex matches nothing" from "the mutation did
  # its job" — which is the same conflation this guard exists to remove.
  # The output is captured before being searched, deliberately. Piping into
  # `grep -q` makes grep exit at the first match, `go test` take SIGPIPE, and the
  # pipeline report failure under `set -o pipefail` — so every regex, including
  # the ones that match nine tests, looked like it matched none.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 120s -v 2>/dev/null || true)"
  if ! printf '%s' "$selected" | grep -q '^=== RUN'; then
    echo "  $id  NO MATCHING TEST — the -run regex selects nothing: $regex"
    FAIL=$((FAIL + 1)); SURVIVORS+=("$id (no matching test: $regex)"); return
  fi


  if ! python3 - "$file" <<PY
import sys
path = sys.argv[1]
s = open(path).read()
$script
open(path, 'w').write(s)
PY
  then
    echo "  $id  COULD NOT PLANT — the anchor text is gone: $desc"
    FAIL=$((FAIL + 1))
    SURVIVORS+=("$id (unplantable)")
    restore
    return
  fi

  if go test "$pkg" -run "$regex" -count=1 >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc")
    FAIL=$((FAIL + 1))
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 9.1A mutation closure"
echo

mutate A01 "unknown fields accepted" internal/fleet/config/document.go \
  's = s.replace("decoder.KnownFields(true)", "decoder.KnownFields(false)")
assert "KnownFields(false)" in s' \
  ./internal/fleet/config 'TestMTC04'

mutate A02 "duplicate YAML keys accepted" internal/fleet/config/document.go \
  's = s.replace("""		var configErr *Error
		if errors.As(err, &configErr) {
			return configErr
		}
		return classifyDecodeError(err)""", """		var configErr *Error
		if errors.As(err, &configErr) {
			return configErr
		}
		if strings.Contains(err.Error(), "already defined") {
			return nil
		}
		return classifyDecodeError(err)""", 1)
assert "already defined\") {" in s' \
  ./internal/fleet/config 'TestMTC14DuplicateYAMLKeyIsRejectedAtEveryLevel'

# A03 must remove BOTH refusals. The explicit branch is redundant with the tag
# allow-list — established by this mutation surviving when it removed only the
# branch — so a faithful "merge keys are accepted" mutation has to do both.
mutate A03 "YAML merge key accepted" internal/fleet/config/document.go \
  's = s.replace("""	if node.Tag == "!!merge" {""", """	if false {""", 1)
s = s.replace("""	"!!seq":  true,""", """	"!!seq":   true,
	"!!merge": true,""", 1)
assert "if false {" in s and "!!merge\": true" in s' \
  ./internal/fleet/config 'TestMTC18MergeKeyIsRejected'

mutate A04 "plaintext scalar password accepted" internal/fleet/config/credential.go \
  's = s.replace("	if value.Kind != yaml.MappingNode {\n		return newError(CategoryCredentialReference, fmt.Sprintf(\n			\"must be a mapping naming exactly one source", "	if false {\n		return newError(CategoryCredentialReference, fmt.Sprintf(\n			\"must be a mapping naming exactly one source", 1)
assert "	if false {" in s' \
  ./internal/fleet/config 'TestMTC06AndS08APlaintextPasswordIsRefusedStructurally'

mutate A05 "env and file together accepted" internal/fleet/config/credential.go \
  's = s.replace("	case fields.Env != \"\" && fields.File != \"\":", "	case false:", 1)
assert "	case false:" in s' \
  ./internal/fleet/config 'TestMTC07BothSourcesAreRefused'

mutate A06 "empty credential reference accepted" internal/fleet/config/credential.go \
  's = s.replace("""	if r.present && r.kind == SourceNone {""", """	if false {""", 1)
s = s.replace("""	default:
		return newError(CategoryCredentialReference,
			"names no source; it must name exactly one of \\"env\\" or \\"file\\"").
			onLine(value.Line)
	}""", """	default:
		return nil
	}""", 1)
assert "	if false {" in s' \
  ./internal/fleet/config 'TestMTC08NeitherSourceIsRefused'

mutate A07 "duplicate target IDs accepted" internal/fleet/config/load.go \
  's = s.replace("		if first, duplicate := seen[block.ID]; duplicate {", "		if first, duplicate := seen[block.ID]; false && duplicate {", 1)
assert "false && duplicate" in s' \
  ./internal/fleet/config 'TestMTC02'

mutate A08 "target count limit removed" internal/fleet/config/load.go \
  's = s.replace("	if len(blocks) > MaxTargets {", "	if false {", 1)
assert "	if false {" in s' \
  ./internal/fleet/config 'TestMTC23AndC30TargetCountBounds'

mutate A09 "config byte limit removed" internal/fleet/config/document.go \
  's = s.replace("	if info.Size() > MaxBytes {", "	if false {", 1)
s = s.replace("	if len(data) > MaxBytes {", "	if false {", 1)
assert s.count("	if false {") >= 2' \
  ./internal/fleet/config 'TestMTC22ConfigByteBound'

mutate A10 "unsupported config version accepted" internal/fleet/config/document.go \
  's = s.replace("	case *probe.Version != Version:", "	case false:", 1)
assert "	case false:" in s' \
  ./internal/fleet/config 'TestMTC15AndC16ConfigVersion'

mutate A11 "arbitrary environment interpolation added" internal/fleet/config/load.go \
  's = s.replace("import (\n\t\"errors\"\n\t\"fmt\"\n\t\"math\"\n\t\"time\"\n)", "import (\n\t\"errors\"\n\t\"fmt\"\n\t\"math\"\n\t\"os\"\n\t\"time\"\n)", 1)
s = s.replace("	if err := checkHostSyntax(block.Host); err != nil {", "	block.Host = os.ExpandEnv(block.Host)\n	if err := checkHostSyntax(block.Host); err != nil {", 1)
assert "os.ExpandEnv" in s' \
  ./test/security 'TestOnlyTheResolverReadsTheEnvironment'

mutate A12 "config package reads the environment" internal/fleet/config/load.go \
  's = s.replace("import (\n\t\"errors\"\n\t\"fmt\"\n\t\"math\"\n\t\"time\"\n)", "import (\n\t\"errors\"\n\t\"fmt\"\n\t\"math\"\n\t\"os\"\n\t\"time\"\n)", 1)
s = s.replace("	source := cleanPath(path)", "	source := cleanPath(path)\n	_ = os.Getenv(\"SVCDOCTOR_DEBUG\")", 1)
assert "os.Getenv" in s' \
  ./test/security 'TestOnlyTheResolverReadsTheEnvironment'

mutate A13 "resolver reveals a secret" internal/fleet/secret/secret.go \
  's = s.replace("	if plaintext.IsEmpty() {", "	_ = security.Reveal(plaintext)\n	if plaintext.IsEmpty() {", 1)
assert "security.Reveal" in s' \
  ./test/security 'TestTheFleetLayerNeverRevealsASecret'

mutate A14 "resolved secrets cached globally" internal/fleet/secret/secret.go \
  's = s.replace("type Resolver struct{}", "var secretCache sync.Map\n\ntype Resolver struct{}", 1)
s = s.replace("import (\n\t\"context\"", "import (\n\t\"context\"\n\t\"sync\"", 1)
assert "sync.Map" in s' \
  ./test/security 'TestTheFleetLayerHasNoSecretCache'

mutate A15 "a resolved secret is reused for the same reference" internal/fleet/secret/secret.go \
  's = s.replace("type Resolver struct{}", "type Resolver struct{ cached map[string]security.Secret }", 1)
s = s.replace("""	case config.SourceFile:
		return resolveFile(ref)

	default:
		return security.Secret{}, refErrorf(ref, "names an unsupported credential source")
	}
}""", """	case config.SourceFile:
		if r.cached == nil {
			r.cached = map[string]security.Secret{}
		}
		if hit, ok := r.cached[ref.Name()]; ok {
			return hit, nil
		}
		got, err := resolveFile(ref)
		if err == nil {
			r.cached[ref.Name()] = got
		}
		return got, err

	default:
		return security.Secret{}, refErrorf(ref, "names an unsupported credential source")
	}
}""", 1)
assert "r.cached" in s' \
  ./internal/fleet/secret 'TestResolutionReadsTheSourceEveryTime'

mutate A16 "the fleet core imports an adapter wire package" internal/fleet/config/load.go \
  's = s.replace("import (\n\t\"errors\"", "import (\n\t_ \"github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire\"\n\n\t\"errors\"", 1)
assert "adapter/rabbitmq/wire" in s' \
  ./test/security 'TestTheFleetCoreReachesNoProtocol'

mutate A17 "a service-specific union appears in the generic core" internal/fleet/config/load.go \
  's = s.replace("	factory, ok := registry.lookup(block.Type)", "	if block.Type == \"postgres\" && block.Host == \"\" {\n		return Target{}, newError(CategoryInvalidField, \"postgres needs a host\")\n	}\n	factory, ok := registry.lookup(block.Type)", 1)
assert "postgres" in s' \
  ./test/security 'TestTheGenericCoreNamesNoService'

mutate A18 "targets sorted instead of kept in declared order" internal/fleet/config/load.go \
  's = s.replace("import (\n\t\"errors\"\n\t\"fmt\"\n\t\"math\"\n\t\"time\"\n)", "import (\n\t\"errors\"\n\t\"fmt\"\n\t\"math\"\n\t\"sort\"\n\t\"time\"\n)", 1)
s = s.replace("	return targets, nil\n}\n\n// validateTarget", "	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })\n	return targets, nil\n}\n\n// validateTarget", 1)
assert "sort.Slice" in s' \
  ./internal/fleet/config 'TestMTC17|TestDeclaredOrderSurvives'

mutate A19 "the raw configuration is retained in the validated model" internal/fleet/config/schema.go \
  's = s.replace("""type Config struct {
	// Version is the configuration version, always Version.
	Version int""", """type Config struct {
	// Raw is the document this was decoded from.
	Raw []byte

	// Version is the configuration version, always Version.
	Version int""", 1)
assert "Raw []byte" in s' \
  ./test/security 'TestAValidatedConfigRetainsNoRawBytes'

mutate A20 "a resolver error carries the secret value" internal/fleet/secret/secret.go \
  's = s.replace("""		case value == "":
			return security.Secret{}, refErrorf(ref,
				"the environment variable is set but empty")""", """		case value == "":
			return security.Secret{}, refErrorf(ref,
				"the environment variable is set but empty: " + value)""", 1)
s = s.replace("""		if value == "" {
			return refErrorf(ref, "the environment variable is set but empty")
		}""", """		if value == "" {
			return refErrorf(ref, "the environment variable is set but empty")
		}
		if len(value) > 0 {
			_ = value
		}""", 1)
s = s.replace("""	if plaintext.IsEmpty() {
		return security.Credential{}, refErrorf(ref, "resolved to an empty credential")
	}""", """	if plaintext.IsEmpty() {
		return security.Credential{}, refErrorf(ref, "resolved to an empty credential")
	}
	if target.Credentials.Username == "__leak__" {
		return security.Credential{}, refErrorf(ref, security.Reveal(plaintext))
	}""", 1)
assert "__leak__" in s' \
  ./test/security 'TestTheFleetLayerNeverRevealsASecret'

echo
AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "RESTORE FAILED — the tree does not match its pre-mutation checksums"
  diff <(echo "$BEFORE") <(echo "$AFTER")
  rm -rf "$BACKUP"
  exit 1
fi
echo "tree restored byte-for-byte (${#FILES[@]} files verified by sha256)"

rm -rf "$BACKUP"

echo
echo "caught: $PASS   survivors: $FAIL"
if [ "$FAIL" -ne 0 ]; then
  printf 'SURVIVOR: %s\n' "${SURVIVORS[@]}"
  exit 1
fi
echo "no survivors"
