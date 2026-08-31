package security_test

import (
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Redis and Valkey production authority guard.
//
// Sixteen structural invariants from Phase 7.5 section 5, each one a property of
// the source rather than a sentence in a record. They exist because the Redis
// contract is almost entirely made of absences — no key is named, no credential
// leaves AUTH, no version is compared, no vendor name is branched on — and an
// absence is the one kind of invariant a behavioural test cannot observe. A test
// that connects to a server and does not see a GET has proved nothing about
// whether some other path would send one.
//
// Every guard here has a planted-mutation proof in the phase record: applied,
// observed failing, restored.

// redisProductionFiles returns every non-test Go file that is part of the Redis
// service surface.
//
// The four directories plus the two single files are the whole of it, and
// TestTheRedisSurfaceIsExactlyTheseFiles fails if a seventh location appears —
// which is what stops a future package from being added outside the reach of
// every guard below.
func redisProductionFiles(t *testing.T) []string {
	t.Helper()
	root := repositoryRoot(t)

	roots := []string{
		"internal/adapter/redis",
		"internal/diagnosis/redis",
		"internal/service/redis",
	}
	singles := []string{
		"internal/app/redis.go",
		"internal/cli/redis.go",
		// Phase 9.1A. It holds no protocol — it decodes the Redis shape of a
		// multi-target configuration — but it is Redis production code, and the
		// point of this list is that every such file is inside the reach of the
		// keyspace and credential guards rather than beside them.
		"internal/fleet/services/redis/redis.go",
	}

	var out []string
	for _, dir := range roots {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	for _, file := range singles {
		path := filepath.Join(root, file)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s is missing: %v", file, err)
		}
		out = append(out, path)
	}

	if len(out) == 0 {
		t.Fatal("no Redis production files found; every guard in this file would pass vacuously")
	}
	return out
}

// relative renders a path the way the failure messages should read.
func relative(t *testing.T, path string) string {
	t.Helper()
	rel, err := filepath.Rel(repositoryRoot(t), path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// stringLiterals returns every string literal in a file, unquoted.
func stringLiterals(file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		out = append(out, strings.Trim(lit.Value, "`\""))
		return true
	})
	return out
}

// renderNode prints an expression for a failure message.
func renderNode(n ast.Node) string {
	var sb strings.Builder
	_ = printer.Fprint(&sb, token.NewFileSet(), n)
	return sb.String()
}

// ---------------------------------------------------------------------------
// 1. The authorized command set
// ---------------------------------------------------------------------------

// authorizedRedisCommands is the whole of what ADR 0063 section 2 permits.
//
// Three. Not "three plus whatever a future step needs", and not a prefix rule: a
// literal set, checked by name, so that adding a fourth is a change to this line
// and therefore a change somebody has to argue for.
var authorizedRedisCommands = map[string]bool{
	"HELLO": true,
	"AUTH":  true,
	"PING":  true,
}

// TestOnlyAuthorizedRedisCommandsCanBeEncoded pins the command surface at the one
// place a command can be constructed.
//
// Two constructors exist and there is no third: the two pre-encoded frames, and
// encodeCommand. So proving the surface means proving what those three things
// can produce, which is what this does rather than scanning for command-looking
// strings anywhere in the tree.
func TestOnlyAuthorizedRedisCommandsCanBeEncoded(t *testing.T) {
	root := repositoryRoot(t)
	connPath := filepath.Join(root, "internal/adapter/redis/wire/conn.go")
	file := parseFile(t, connPath)

	frames := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		name := spec.Names[0].Name
		if !strings.HasSuffix(name, "Frame") {
			return true
		}
		frames[name] = renderNode(spec.Values[0])
		return true
	})

	want := map[string]string{
		"helloFrame": `[]byte("*1\r\n$5\r\nHELLO\r\n")`,
		"pingFrame":  `[]byte("*1\r\n$4\r\nPING\r\n")`,
	}
	// The frames and the allowlist have to agree, or one of them is describing a
	// surface the other does not.
	for name, frame := range want {
		command := strings.ToUpper(strings.TrimSuffix(name, "Frame"))
		if !authorizedRedisCommands[command] {
			t.Errorf("%s builds %s, which authorizedRedisCommands does not allow", name, command)
		}
		if !strings.Contains(frame, command) {
			t.Errorf("%s does not encode %s", name, command)
		}
	}
	if len(frames) != len(want) {
		t.Fatalf("found %d pre-encoded frames %v, want exactly %d", len(frames), frames, len(want))
	}
	for name, expected := range want {
		got, ok := frames[name]
		if !ok {
			t.Errorf("%s no longer exists; this guard would stop describing the command surface", name)
			continue
		}
		if got != expected {
			t.Errorf("%s is %s, want %s", name, got, expected)
		}
	}
}

// TestEncodeCommandOnlyEverBuildsAUTH pins the one dynamic constructor.
//
// encodeCommand is the only way a command with arguments can be built, and every
// production call passes the literal "AUTH". A call passing anything else — a
// variable, a different literal, a concatenation — fails here.
//
// # Why two call sites are correct and one would be worse
//
// ADR 0064 section 5 requires the operator's AUTH form to be sent verbatim,
// because the one-argument and two-argument forms have different observable
// behaviour against a `nopass` user. Two forms are two frames. Collapsing them
// into one call over a built slice would satisfy a count but lose the literal,
// and this guard would no longer be able to read the command name from the
// source at all — so the shape it accepts is "every call is AUTH, and they all
// live in one function", not "there is one call".
func TestEncodeCommandOnlyEverBuildsAUTH(t *testing.T) {
	calls := 0
	callers := map[string]bool{}
	for _, path := range redisProductionFiles(t) {
		file := parseFile(t, path)
		enclosing := ""
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "encodeCommand" {
				callers[relative(t, path)+"."+enclosing] = true
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "encodeCommand" {
				return true
			}
			calls++
			if len(call.Args) == 0 {
				t.Errorf("%s calls encodeCommand with no command name", relative(t, path))
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s calls encodeCommand with a non-literal command name %s; "+
					"the command surface must be readable from the source",
					relative(t, path), renderNode(call.Args[0]))
				return true
			}
			name := strings.Trim(lit.Value, `"`)
			if name != "AUTH" {
				t.Errorf("%s builds the command %q; only AUTH is built dynamically "+
					"(ADR 0063 section 2)", relative(t, path), name)
			}
			return true
		})
	}
	if calls == 0 {
		t.Fatal("nothing calls encodeCommand; this guard would pass vacuously")
	}
	if len(callers) != 1 {
		t.Errorf("encodeCommand is called from %v, want exactly one function", callers)
	}
	if want := "internal/adapter/redis/wire/auth.go.SendAuth"; !callers[want] {
		t.Errorf("encodeCommand callers are %v, want only %s", callers, want)
	}
}

// ---------------------------------------------------------------------------
// 2-8. Absences: keys, and the commands that would name one
// ---------------------------------------------------------------------------

// forbiddenRedisCommands are commands no Redis production file may name.
//
// Each is here for a stated reason rather than as a blocklist of things that
// sound dangerous:
//
//	GET SET DEL EXISTS TYPE SCAN KEYS   name a key, or enumerate the keyspace
//	ROLE INFO                           excluded by ADR 0063 section 10
//	CLUSTER                             topology is observed, never asked for
//	SENTINEL                            detection only, never diagnosis
//	SELECT                              a database index BASIC cannot observe
//	RESET                               would make re-authentication expressible
//	CLIENT ECHO COMMAND SUBSCRIBE       outside the allowlist
//	EVAL EVALSHA FUNCTION SCRIPT        would execute code on the endpoint
//
// The match is exact and case-sensitive, which is safe because no error prefix
// or normalized value in the Redis surface equals any of these: MOVED, ASK and
// CLUSTERDOWN are prefixes, and CLUSTERDOWN is not CLUSTER.
var forbiddenRedisCommands = []string{
	"GET", "SET", "DEL", "EXISTS", "TYPE", "SCAN", "KEYS",
	"ROLE", "INFO", "CLUSTER", "SENTINEL", "SELECT", "RESET",
	"CLIENT", "ECHO", "COMMAND", "SUBSCRIBE",
	"EVAL", "EVALSHA", "FUNCTION", "SCRIPT",
	"MGET", "MSET", "UNLINK", "TOUCH", "DUMP", "RESTORE", "MIGRATE",
	"FLUSHALL", "FLUSHDB", "SWAPDB", "CONFIG", "DEBUG", "SHUTDOWN",
}

// TestNoRedisProductionFileNamesAForbiddenCommand is the blunt half of the
// keyspace contract.
//
// The precise half is TestEncodeCommandOnlyEverBuildsAUTH, which proves what can
// be *constructed*. This proves the weaker but broader thing: the name does not
// appear as a literal anywhere in the surface, so a helper that assembled one by
// hand, or a constant staged for later, fails before it is ever called.
//
// **This is the mechanical reason MOVED and ASK stay unreachable.** They require
// a key argument (redis/src/server.c:4609-4616), and nothing here can name one.
func TestNoRedisProductionFileNamesAForbiddenCommand(t *testing.T) {
	for _, path := range redisProductionFiles(t) {
		for _, literal := range stringLiterals(parseFile(t, path)) {
			for _, forbidden := range forbiddenRedisCommands {
				if literal == forbidden {
					t.Errorf("%s contains the string literal %q.\n\n"+
						"Redis BASIC names no key and sends only HELLO, AUTH and PING. "+
						"See ADR 0063 section 11.", relative(t, path), forbidden)
				}
			}
		}
	}
}

// TestNoRedisCommandCarriesAKeyArgument proves the property the absence is for.
//
// The three authorized commands take no key: HELLO and PING are argument-free
// constants, and AUTH's arguments are a username and a secret. So the set of
// values that can reach a command frame is closed, and it contains no key.
func TestNoRedisCommandCarriesAKeyArgument(t *testing.T) {
	root := repositoryRoot(t)
	file := parseFile(t, filepath.Join(root, "internal/adapter/redis/wire/auth.go"))

	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "encodeCommand" {
			return true
		}
		found = true
		for i, arg := range call.Args[1:] {
			rendered := renderNode(arg)
			switch rendered {
			case "username", "password":
			default:
				t.Errorf("AUTH argument %d is %s; only the username and the secret may "+
					"reach a command frame", i+1, rendered)
			}
		}
		return true
	})
	if !found {
		t.Fatal("no encodeCommand call in auth.go; this guard would pass vacuously")
	}
}

// ---------------------------------------------------------------------------
// 9-13. The credential surface
// ---------------------------------------------------------------------------

// TestRedisHelloCannotCarryACredential is the load-bearing structural defence of
// ADR 0064.
//
// Redis echoes up to 128 bytes of an unknown command's *arguments* back to the
// caller and into its own log (redis/src/server.c:4378-4389), and the redaction
// that would prevent it lives inside helloCommand and so never runs on that path.
// A HELLO with no arguments has nothing to leak.
//
// Two independent assertions, because either alone could be satisfied by a
// mutation the other catches: the frame constant is exactly the zero-argument
// form, and no command constructor is ever handed "HELLO".
func TestRedisHelloCannotCarryACredential(t *testing.T) {
	root := repositoryRoot(t)
	conn := parseFile(t, filepath.Join(root, "internal/adapter/redis/wire/conn.go"))

	exact := false
	ast.Inspect(conn, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "helloFrame" {
			return true
		}
		if renderNode(spec.Values[0]) == `[]byte("*1\r\n$5\r\nHELLO\r\n")` {
			exact = true
		}
		return true
	})
	if !exact {
		t.Error("helloFrame is not the exact zero-argument frame; a credential, a protocol " +
			"version or a client name in HELLO is the defect ADR 0064 section 1 records")
	}

	for _, path := range redisProductionFiles(t) {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "encodeCommand" || len(call.Args) == 0 {
				return true
			}
			if strings.Contains(renderNode(call.Args[0]), "HELLO") {
				t.Errorf("%s builds HELLO through the argument-taking constructor; "+
					"HELLO must stay a constant with no arguments", relative(t, path))
			}
			return true
		})
	}
}

// TestExactlyOneRedisAuthWriterExists pins the credential-bearing surface.
//
// One call to SendAuth, in the adapter, and nowhere else. A second call site is
// a second attempt whatever guards surround it, and a call site outside the
// adapter would be orchestration speaking the protocol.
func TestExactlyOneRedisAuthWriterExists(t *testing.T) {
	sites := map[string]int{}
	for _, path := range redisProductionFiles(t) {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SendAuth" {
				return true
			}
			sites[relative(t, path)]++
			return true
		})
	}

	total := 0
	for path, count := range sites {
		total += count
		if path != "internal/adapter/redis/authenticate.go" {
			t.Errorf("%s calls SendAuth; only the adapter's Authenticate may", path)
		}
	}
	if total != 1 {
		t.Errorf("found %d SendAuth call site(s), want exactly 1 (ADR 0064 section 4)", total)
	}
}

// TestTheRedisAuthWriterIsNotInALoop closes the shape a count cannot.
//
// One call site inside a `for` is unbounded attempts with a passing call-site
// count. The same applies one layer up: the composition root calls
// redis.Authenticate once, and not from a loop over candidates.
func TestTheRedisAuthWriterIsNotInALoop(t *testing.T) {
	for _, target := range []struct {
		file string
		call string
	}{
		{"internal/adapter/redis/authenticate.go", "SendAuth"},
		{"internal/app/redis.go", "Authenticate"},
	} {
		path := filepath.Join(repositoryRoot(t), target.file)
		file := parseFile(t, path)

		var loops []ast.Node
		found := false
		ast.Inspect(file, func(n ast.Node) bool {
			switch n.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				loops = append(loops, n)
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != target.call {
				return true
			}
			found = true
			for _, loop := range loops {
				if loop.Pos() <= call.Pos() && call.End() <= loop.End() {
					t.Errorf("%s calls %s inside a loop; a credential-bearing command must "+
						"be unrepeatable by construction", target.file, target.call)
				}
			}
			return true
		})
		if !found {
			t.Errorf("%s no longer calls %s; this guard would pass vacuously",
				target.file, target.call)
		}
	}
}

// TestExactlyOneRedisRevealAndSecretForExist keeps the secret path singular
// inside the service.
//
// The repository-wide count lives in TestRevealHasOneProductionCallSitePerService.
// This is the service-local half: within the Redis surface there is one Reveal
// and one SecretFor, and each is in the file authorized to hold it.
func TestExactlyOneRedisRevealAndSecretForExist(t *testing.T) {
	authorized := map[string]string{
		"Reveal":    "internal/adapter/redis/wire/auth.go",
		"SecretFor": "internal/adapter/redis/authenticate.go",
	}
	counts := map[string]int{}

	for _, path := range redisProductionFiles(t) {
		rel := relative(t, path)
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			want, tracked := authorized[sel.Sel.Name]
			if !tracked {
				return true
			}
			counts[sel.Sel.Name]++
			if rel != want {
				t.Errorf("%s calls %s; only %s may", rel, sel.Sel.Name, want)
			}
			return true
		})
	}

	for name := range authorized {
		if counts[name] != 1 {
			t.Errorf("found %d %s call(s) in the Redis surface, want exactly 1",
				counts[name], name)
		}
	}
}

// TestRedisHasNoDiscoveredEndpointCredentialPath proves the topology rule holds
// by absence rather than by policy.
//
// v1 discovers no endpoint at all, so the strongest available statement is that
// nothing in the surface can even name one: no advertised endpoint type, no
// redirect follow, no second sweep. A credential cannot travel to a discovered
// node when no discovered node exists.
func TestRedisHasNoDiscoveredEndpointCredentialPath(t *testing.T) {
	forbidden := []string{"Advertised", "advertised", "Discovered", "discovered", "Redirect"}
	for _, path := range redisProductionFiles(t) {
		file := parseFile(t, path)
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, word := range forbidden {
				if strings.Contains(ident.Name, word) {
					t.Errorf("%s names %s; Redis BASIC discovers no endpoint, and a "+
						"credential may never reach one (ADR 0065 section 6)",
						relative(t, path), ident.Name)
				}
			}
			return true
		})
	}
}

// ---------------------------------------------------------------------------
// 14-15. One implementation, no arithmetic
// ---------------------------------------------------------------------------

// TestNoProductionCodeBranchesOnImplementationName pins ADR 0066 section 6.
//
// One adapter serves Redis and Valkey because every step of the frozen journey
// behaves identically on both. A comparison against "redis" or "valkey" would be
// the first half of a fork, and it would also be wrong: Valkey reports "redis"
// with a Redis version number when extended-redis-compat is enabled, so a branch
// on the name is a branch on a configurable self-description.
func TestNoProductionCodeBranchesOnImplementationName(t *testing.T) {
	names := map[string]bool{"redis": true, "valkey": true, "Redis": true, "Valkey": true}

	for _, path := range redisProductionFiles(t) {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			binary, ok := n.(*ast.BinaryExpr)
			if !ok || (binary.Op != token.EQL && binary.Op != token.NEQ) {
				return true
			}
			for _, side := range []ast.Expr{binary.X, binary.Y} {
				lit, ok := side.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if names[strings.Trim(lit.Value, `"`)] {
					t.Errorf("%s compares against the implementation name in %s.\n\n"+
						"Behaviour is decided by capability discovery, never by who the "+
						"endpoint says it is (ADR 0066 section 6).",
						relative(t, path), renderNode(binary))
				}
			}
			return true
		})
	}
}

// TestNoProductionCodeDoesVersionArithmetic pins ADR 0066 section 5.
//
// Valkey's version numbers are on an unrelated line from Redis's, and either can
// be configured to report the other's, so a comparison is meaningless even when
// it parses. The version is carried as an opaque string and never ordered,
// compared, split or parsed.
func TestNoProductionCodeDoesVersionArithmetic(t *testing.T) {
	ordering := map[token.Token]bool{
		token.LSS: true, token.GTR: true, token.LEQ: true, token.GEQ: true,
	}

	for _, path := range redisProductionFiles(t) {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BinaryExpr:
				if !ordering[node.Op] {
					return true
				}
				rendered := renderNode(node)
				if strings.Contains(rendered, "Version") || strings.Contains(rendered, "version") {
					t.Errorf("%s orders a version in %s; the version is opaque",
						relative(t, path), rendered)
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "strconv" {
					return true
				}
				for _, arg := range node.Args {
					if strings.Contains(renderNode(arg), "ersion") {
						t.Errorf("%s parses a version with strconv.%s; the version is opaque",
							relative(t, path), sel.Sel.Name)
					}
				}
			}
			return true
		})
	}
}

// ---------------------------------------------------------------------------
// 16. The wire boundary
// ---------------------------------------------------------------------------

// TestRawPeerTextCannotCrossTheWireBoundary pins ADR 0066 section 3
// structurally.
//
// The decoded frame type and every one of its fields are unexported, so a
// package outside internal/adapter/redis/wire cannot hold peer bytes even by
// accident. What crosses is a normalized ErrorPrefix drawn from a closed set,
// plus identity strings that were charset-checked and length-bounded.
//
// The behavioural half — a secret canary planted in hostile error text, proved
// absent from the report — is in the wire package's own tests and in the
// integration suite. This is the structural half, and it is the one a
// behavioural test cannot give: it holds for paths no fixture exercises.
func TestRawPeerTextCannotCrossTheWireBoundary(t *testing.T) {
	root := repositoryRoot(t)
	resp := parseFile(t, filepath.Join(root, "internal/adapter/redis/wire/resp.go"))

	foundType := false
	ast.Inspect(resp, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "reply" {
			return true
		}
		foundType = true
		if spec.Name.IsExported() {
			t.Error("the decoded frame type is exported; peer bytes must not be holdable " +
				"outside this package")
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			t.Fatal("reply is not a struct")
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				if name.IsExported() {
					t.Errorf("reply.%s is exported; every field of a decoded frame must "+
						"stay unreachable outside the wire package", name.Name)
				}
			}
		}
		return false
	})
	if !foundType {
		t.Fatal("the reply type is gone; this guard would pass vacuously")
	}

	// The exported results are the whole boundary, and each field is named here
	// so that adding one is a change to this list.
	authorizedFields := map[string][]string{
		"Hello": {"Prefix", "Server", "Version", "Proto", "Mode", "Role"},
		"Auth":  {"Prefix"},
		"Ping":  {"Prefix"},
	}
	seen := map[string][]string{}
	for _, name := range []string{"hello.go", "auth.go", "ping.go"} {
		file := parseFile(t, filepath.Join(root, "internal/adapter/redis/wire", name))
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			if _, tracked := authorizedFields[spec.Name.Name]; !tracked {
				return true
			}
			for _, field := range structType.Fields.List {
				for _, fieldName := range field.Names {
					seen[spec.Name.Name] = append(seen[spec.Name.Name], fieldName.Name)
				}
			}
			return true
		})
	}
	for typeName, want := range authorizedFields {
		got := seen[typeName]
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("wire.%s has fields %v, want exactly %v.\n\n"+
				"A field carrying a peer's message text would cross the boundary "+
				"ADR 0066 draws.", typeName, got, want)
		}
	}
}

// TestNoRedisPackageOutsideWireReadsAPrefixConstantByValue keeps classification
// where it was authorized.
//
// Diagnosis reads the normalized prefix as an attribute the adapter recorded. It
// must not re-derive one, and it must not compare against a raw message: the
// only strings it may match are the closed-set values the wire package declared.
func TestNoRedisPackageOutsideWireReadsAPrefixConstantByValue(t *testing.T) {
	root := repositoryRoot(t)
	for _, dir := range []string{"internal/diagnosis/redis", "internal/app", "internal/cli"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			for _, imported := range parseFile(t, path).Imports {
				if strings.Contains(imported.Path.Value, "adapter/redis/wire") {
					t.Errorf("%s imports the Redis wire package; only the adapter may",
						relative(t, path))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
}

// TestTheRedisSurfaceIsExactlyTheseFiles keeps every guard above in contact with
// the whole service.
//
// redisProductionFiles enumerates three directories and two files. A Redis
// package added anywhere else would be outside the reach of the keyspace guard,
// the credential guards and the vendor-branch guard at once — and nothing would
// have said so. This is the list that has to change first.
func TestTheRedisSurfaceIsExactlyTheseFiles(t *testing.T) {
	root := repositoryRoot(t)

	var found []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin", "dist", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel := relative(t, path)
		switch {
		case strings.Contains(rel, "/redis/"), strings.HasSuffix(rel, "/redis.go"):
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}

	known := map[string]bool{}
	for _, path := range redisProductionFiles(t) {
		known[relative(t, path)] = true
	}
	for _, rel := range found {
		if !known[rel] {
			t.Errorf("%s is Redis production code outside redisProductionFiles.\n\n"+
				"Add it there rather than leaving it outside every guard in this file.", rel)
		}
	}
	if len(found) == 0 {
		t.Fatal("no Redis production files matched; this guard would pass vacuously")
	}
}

// ---------------------------------------------------------------------------
// The two mutation surfaces that do not exist
// ---------------------------------------------------------------------------

// Phase 7.5's mutation matrix has 42 entries and 40 of them are executable.
//
// Two cannot be instantiated, because the surface they would mutate is absent
// from the product:
//
//	#8  AUTH to a discovered endpoint — Redis BASIC discovers no endpoint
//	#9  a private key rendered        — Redis BASIC accepts no private key
//
// **Absence is not evidence on its own.** A surface that is missing today can
// arrive tomorrow and take its mutation with it, unnoticed, because a matrix
// entry nobody can plant is an entry nobody re-checks. The two guards below are
// what make the absence a checked property instead of a footnote: each fails the
// moment its surface appears, which is the moment its mutation becomes
// executable and has to be planted.
//
// The honest accounting is therefore "40 executable mutations planted and
// caught, 2 structurally absent surfaces guarded" — never "42 planted".

// TestNoRedisDiscoveryOrTopologyTraversalSurfaceExists guards mutation #8.
//
// A discovered-endpoint AUTH needs three things that do not exist: a topology
// command to learn an endpoint from, a second transport sweep to reach it, and a
// credential path that would accept it. This asserts the first two are absent —
// the third is already pinned by TestExactlyOneRedisAuthWriterExists.
func TestNoRedisDiscoveryOrTopologyTraversalSurfaceExists(t *testing.T) {
	// A topology command would have to be named to be sent, and the allowlist
	// guard already refuses every CLUSTER form. What this adds is the *shape*: no
	// second sweep, no advertised endpoint type, no redirect follower.
	forbidden := map[string]string{
		"transport.Run": "a second transport sweep would be the mechanism by which a " +
			"discovered endpoint is reached; the composition root runs exactly one",
		"Advertised":  "an advertised endpoint type is the thing a credential could travel to",
		"Discovered":  "same",
		"Redirect":    "following a redirect is how an endpoint svcdoctor never named becomes reachable",
		"FollowMoved": "same",
	}

	sweeps := 0
	for _, path := range redisProductionFiles(t) {
		rel := relative(t, path)
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			// transport.Run is legitimate exactly once, in the composition root.
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "transport" {
						sweeps++
						if rel != "internal/app/redis.go" {
							t.Errorf("%s runs a transport sweep; only the composition "+
								"root may, and only once", rel)
						}
					}
				}
			}
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for word, why := range forbidden {
				if word == "transport.Run" {
					continue
				}
				if strings.Contains(ident.Name, word) {
					t.Errorf("%s names %s.\n\nMutation #8 (AUTH to a discovered endpoint) "+
						"is currently unwritable because %s. If this surface is being "+
						"added, #8 becomes executable and must be planted.",
						rel, ident.Name, why)
				}
			}
			return true
		})
	}

	if sweeps != 1 {
		t.Errorf("the Redis surface runs %d transport sweeps, want exactly 1.\n\n"+
			"More than one is the shape a discovered-endpoint probe would take.", sweeps)
	}
}

// TestNoRedisPrivateKeyOrClientCertificateSurfaceExists guards mutation #9.
//
// A rendered private key needs a private key. svcdoctor accepts none: ADR 0064
// section 8 defers mutual TLS, `internal/probe/tls.Params` carries no
// certificate field, and the Redis CLI defines no certificate flag. This asserts
// the Redis half, and asserts the shared half has not grown one either — because
// the day it does, #9 becomes executable for every service at once.
func TestNoRedisPrivateKeyOrClientCertificateSurfaceExists(t *testing.T) {
	forbidden := []string{
		"PrivateKey", "privateKey", "ClientCert", "clientCert",
		"KeyFile", "keyFile", "CertFile", "certFile", "Certificates",
	}

	for _, path := range redisProductionFiles(t) {
		rel := relative(t, path)
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, word := range forbidden {
				if ident.Name == word {
					t.Errorf("%s names %s.\n\nMutation #9 (a private key rendered) is "+
						"currently unwritable because no key material enters svcdoctor. "+
						"If a client-certificate surface is being added, #9 becomes "+
						"executable and must be planted.", rel, ident.Name)
				}
			}
			return true
		})
	}

	// The shared transport params are the place the capability would actually
	// land, so the guard reaches there too rather than only at the Redis files.
	shared := filepath.Join(repositoryRoot(t), "internal/probe/tls/params.go")
	ast.Inspect(parseFile(t, shared), func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok {
			return true
		}
		for _, name := range field.Names {
			if strings.Contains(name.Name, "Certificate") || strings.Contains(name.Name, "Key") {
				t.Errorf("internal/probe/tls.Params gained the field %s.\n\n"+
					"That is the mutual-TLS surface ADR 0064 section 8 defers. Its "+
					"arrival makes mutation #9 executable, gives the two banned "+
					"TLS client-certificate failure classes a producer, and needs a "+
					"redaction owner for the key material.", name.Name)
			}
		}
		return true
	})
}
