package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The zero-application-topology contract, in executable form.
//
// RabbitMQ BASIC diagnoses reachability. It never opens a channel, never names a
// queue or an exchange, never publishes or consumes, and never speaks the
// management HTTP API. ADR 0067 §2 fixes the method allowlist and calls the
// absence **structural rather than merely unused**, which is what these guards
// hold the tree to.
//
// # Why structural guards and not only runtime counters
//
// A runtime counter can only say "this run created no queue". These say the
// binary cannot express one. That is the stronger claim, it is the one ADR 0067
// asks for, and it is the only kind available for the methods a healthy broker
// would accept silently.
//
// The integration suite adds the runtime half: after every scenario has run, the
// brokers still hold no queue and no non-built-in exchange. Neither half creates
// a queue or an exchange in order to prove absence.

// rabbitmqProductionDirs are the packages that may speak AMQP.
var rabbitmqProductionDirs = []string{
	"internal/adapter/rabbitmq",
	"internal/adapter/rabbitmq/wire",
	"internal/diagnosis/rabbitmq",
	"internal/service/rabbitmq",
}

// rabbitmqProductionSource returns every non-test Go file in those packages,
// with comments left in place for the import guard and stripped for the rest.
func rabbitmqProductionSource(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range rabbitmqProductionDirs {
		full := filepath.Join(repoRootDir(t), dir)
		entries, err := os.ReadDir(full)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(full, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			out[filepath.Join(dir, name)] = string(data)
		}
	}
	if len(out) == 0 {
		t.Fatal("no RabbitMQ production source was found; this guard would pass vacuously")
	}
	return out
}

// repoRootDir walks up to the module root.
func repoRootDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the working directory")
		}
		dir = parent
	}
}

// TestTheWireEncoderCanExpressOnlyTheConnectionClass pins ADR 0067 §2.
//
// `encodeMethod` takes a `connectionMethod` and writes `classConnection` as a
// constant, so there is no channel id, no class parameter and no escape hatch.
// A method outside the connection class is unrepresentable rather than merely
// unused, and adding one would require editing the type's meaning.
func TestTheWireEncoderCanExpressOnlyTheConnectionClass(t *testing.T) {
	source := rabbitmqProductionSource(t)
	frame, ok := source["internal/adapter/rabbitmq/wire/frame.go"]
	if !ok {
		t.Fatal("wire/frame.go is missing; the encoder guard has nothing to read")
	}

	if !strings.Contains(frame, "const classConnection uint16 = 10") {
		t.Error("classConnection is no longer a fixed constant")
	}
	if !strings.Contains(frame, "func encodeMethod(m connectionMethod, payload []byte) []byte") {
		t.Error("encodeMethod no longer takes a connectionMethod; a class or channel " +
			"parameter would make a non-connection method expressible")
	}
	if !strings.Contains(frame, "binary.BigEndian.AppendUint16(body, classConnection)") {
		t.Error("the encoder no longer writes classConnection as a constant")
	}

	// The outbound method set is exactly the five ADR 0067 §2 allows.
	for _, want := range []string{
		"mStartOk connectionMethod = 11",
		"mTuneOk  connectionMethod = 31",
		"mOpen    connectionMethod = 40",
		"mClose   connectionMethod = 50",
		"mCloseOk connectionMethod = 51",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("the outbound method set no longer declares %q", want)
		}
	}
	// And nothing else. Any sixth outbound method is a new capability.
	if got := strings.Count(frame, "connectionMethod = "); got != 5 {
		t.Errorf("the outbound method set declares %d methods, want exactly 5", got)
	}
}

// TestNoRabbitMQProductionFileNamesAnApplicationMethod is the scope guard.
//
// Each id below is a class svcdoctor must never send. Naming one in production
// source is the first edit any of them would need.
func TestNoRabbitMQProductionFileNamesAnApplicationMethod(t *testing.T) {
	forbidden := []string{
		// AMQP classes outside connection.
		"classChannel", "classExchange", "classQueue", "classBasic", "classTx",
		// Their methods, by the name a reader would reach for.
		"Channel.Open", "channel.open", "ChannelOpen",
		"Queue.Declare", "queue.declare", "QueueDeclare",
		"Exchange.Declare", "exchange.declare", "ExchangeDeclare",
		"Basic.Publish", "basic.publish", "BasicPublish",
		"Basic.Consume", "basic.consume", "BasicConsume",
		"Basic.Get", "basic.get", "BasicGet",
	}
	for path, code := range rabbitmqProductionSource(t) {
		stripped := stripGoComments(code)
		for _, name := range forbidden {
			if strings.Contains(stripped, name) {
				t.Errorf("%s names %q; RabbitMQ BASIC opens no channel and touches no "+
					"queue or exchange (ADR 0067 §2)", path, name)
			}
		}
	}
}

// TestNoRabbitMQProductionFileSpeaksTheManagementAPI pins ADR 0067 §8.
//
// The management HTTP API is absent, not deferred to a flag. It is a second
// protocol on a second port with its own authentication, and BASIC diagnoses the
// AMQP endpoint the operator named.
func TestNoRabbitMQProductionFileSpeaksTheManagementAPI(t *testing.T) {
	for path, code := range rabbitmqProductionSource(t) {
		stripped := stripGoComments(code)
		for _, name := range []string{
			`"net/http"`, "http.Get", "http.Post", "http.NewRequest", "http.Client",
			"/api/overview", "/api/vhosts", "/api/queues", "15672",
		} {
			if strings.Contains(stripped, name) {
				t.Errorf("%s references %q; the management API is absent rather than "+
					"deferred (ADR 0067 §8)", path, name)
			}
		}
	}
}

// TestTheZeroTopologyGuardsCanFail proves the three guards above are not vacuous.
//
// Each is re-run against source that carries exactly the defect it exists to
// catch. A guard that cannot fail is documentation.
func TestTheZeroTopologyGuardsCanFail(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		forbid   []string
		wantHits bool
	}{
		{
			name:     "an application method is named",
			code:     "package wire\nfunc send() { encodeMethod(mQueueDeclare, nil) }\n// Queue.Declare\n",
			forbid:   []string{"mQueueDeclare"},
			wantHits: true,
		},
		{
			name:     "a management call appears",
			code:     "package wire\nimport \"net/http\"\nvar _ = http.Get\n",
			forbid:   []string{`"net/http"`, "http.Get"},
			wantHits: true,
		},
		{
			name:     "clean source",
			code:     "package wire\nfunc send() { encodeMethod(mStartOk, nil) }\n",
			forbid:   []string{"mQueueDeclare", `"net/http"`},
			wantHits: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stripped := stripGoComments(tc.code)
			hit := false
			for _, name := range tc.forbid {
				if strings.Contains(stripped, name) {
					hit = true
				}
			}
			if hit != tc.wantHits {
				t.Errorf("detector hit = %v, want %v; the guard cannot distinguish a "+
					"defect from clean source", hit, tc.wantHits)
			}
		})
	}
}

// stripGoComments removes comments so a guard can forbid an implementation
// without forbidding the sentence that explains why it is forbidden.
func stripGoComments(code string) string {
	var sb strings.Builder
	i := 0
	for i < len(code) {
		switch {
		case strings.HasPrefix(code[i:], "//"):
			j := strings.IndexByte(code[i:], '\n')
			if j < 0 {
				return sb.String()
			}
			i += j
		case strings.HasPrefix(code[i:], "/*"):
			j := strings.Index(code[i:], "*/")
			if j < 0 {
				return sb.String()
			}
			i += j + 2
		default:
			sb.WriteByte(code[i])
			i++
		}
	}
	return sb.String()
}
