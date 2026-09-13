package security_test

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The recommendation-classification contract, as a corpus. Closed at Phase 13.1C.
//
// ADR 0097 section 2.1: a production diagnosis rule may not decline to classify
// its own advice. Phase 13.1B classified the 55 whose prose Phase 13.1A found
// safe as written and left 9 for Phase 13.1C; Phase 13.1C reviewed those nine,
// rewrote each one and classified it, so the invariant is now enforced **at
// zero** by TestNoProductionRuleBuildsAnUnclassifiedRecommendation and the
// shrink-only allowlist that stood in for it is deleted.
//
// # Why the corpus is a table and not derived
//
// A derived guard would answer "is every recommendation classified" and could not
// answer "is each one classified as the freeze says". The migration's whole claim
// is that it changed metadata and not meaning, so the expected metadata has to be
// written down by a person and compared, which is the same reason
// realTestedPlatforms in internal/cli is hand-maintained.
//
// Completeness is not taken on trust: TestEveryRecommendationConstantIsAccountedFor
// scans the production tree and fails if the table and the tree disagree in either
// direction.

// migrationGroup is which half of the freeze a recommendation belongs to.
type migrationGroup int

const (
	// migrated is one of the 55 Phase 13.1B classified.
	migrated migrationGroup = iota
	// alreadyClassified is one of the 9 that shipped classified in Phases 10.2,
	// 10.3 and 12.1C.
	alreadyClassified
	// rewritten is one of the 9 Phase 13.1C reviewed. Each one's action
	// instructed, or could be read as instructing, a change to the target
	// (Phase 13.1A section 8.3); each was rewritten as bounded next evidence and
	// then classified. **The digests on these rows are the new text**, which is
	// what makes "only these nine moved" checkable in the same table that proves
	// the other 64 did not.
	rewritten
)

// recommendationRecord is one row of the frozen corpus.
type recommendationRecord struct {
	rec      string
	pkg      string
	constant string
	code     domain.FindingCode
	group    migrationGroup
	// safety and selfCollectable are meaningful only when the row is classified.
	safety          domain.SafetyClass
	selfCollectable bool
	// actionSHA256 is the hex SHA-256 of the action text as it stood at the
	// Phase 13.1B baseline. It is what makes "metadata only" checkable.
	actionSHA256 string
}

var recommendationCorpus = []recommendationRecord{
	{"REC-004", "transport", "recommendCertificateNotValidNow", "TLS_CERTIFICATE_NOT_VALID_NOW", migrated, domain.SafetyCompare, false, "1d34c7a185fb5c3c0903825f587833c465d9d75e480b10c32b84e04c33b9336a"},
	{"REC-005", "transport", "recommendChainNotTrusted", "TLS_CHAIN_NOT_TRUSTED", migrated, domain.SafetyCompare, false, "2554aecc366cbaf606578b953e4eb4c8f35cee400677afd8c1477235facc2721"},
	{"REC-003", "transport", "recommendConnectionNotEstablished", "TCP_CONNECTION_NOT_ESTABLISHED", migrated, domain.SafetyVerify, false, "029814d6b8fd0eeb06e612c9fef0ddac2a72e087e833832ea19644066ae8218b"},
	{"REC-006", "transport", "recommendEndpointDoesNotSpeakTLS", "TLS_ENDPOINT_DOES_NOT_SPEAK_TLS", migrated, domain.SafetyObserve, false, "8ee2b01f375edd6eae4f1c5c4788e5d4880a3073752827af995c14ec110e3dff"},
	{"REC-007", "transport", "recommendHandshakeNotCompleted", "TLS_HANDSHAKE_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "0a8fd5a7dd71937e33880f40ca20c82527f6148822dfac0a3cf2e7d5497e5a04"},
	{"REC-008", "transport", "recommendIdentityMismatch", "TLS_IDENTITY_MISMATCH", migrated, domain.SafetyCompare, false, "03ac4fccd0108f3531142801190a5819a0b89254b2c245043bf731674236f28e"},
	{"REC-001", "transport", "recommendNameNotResolved", "DNS_NAME_NOT_RESOLVED", migrated, domain.SafetyVerify, false, "de848a8e3f1070dce173eea34c6a3c641e04318b9e43f81a2a5e323979dd5c9f"},
	{"REC-002", "transport", "recommendResolutionFailed", "DNS_RESOLUTION_FAILED", migrated, domain.SafetyVerify, false, "41600a5cc255eb5bc45393d168bcd5e580a894d7eb3cef3f4581f5a1515bee7e"},
	{"REC-009", "kafka", "recommendAPIVersionsNotCompleted", "KAFKA_API_VERSIONS_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "88e652796d695eb1cbc708973237d0ef39472409ac5abbb20e7c62f0044aab85"},
	{"REC-010", "kafka", "recommendAuthenticationNotCompleted", "KAFKA_AUTHENTICATION_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "a6ab3dfdbbb9bb4253576e7054eb256ec507cd41f4ea2dabcad9fdda22d4b227"},
	{"REC-011", "kafka", "recommendCredentialNotConfigured", "KAFKA_CREDENTIAL_NOT_CONFIGURED", migrated, domain.SafetyObserve, false, "660b4f972971c0513ba91b6e7f14d1dd5dff1e2389f4955b8c26a0558f6e4bd9"},
	{"REC-012", "kafka", "recommendCredentialWithheld", "KAFKA_CREDENTIAL_WITHHELD", rewritten, domain.SafetyObserve, false, "7cb5ece14f0d4de3197a2a64f1c87356a4870e5c46cda341a2d9c4c45cf0be0f"},
	{"REC-013", "kafka", "recommendCredentialsRejected", "KAFKA_CREDENTIALS_REJECTED", migrated, domain.SafetyVerify, false, "b874815f7c4f98a23892f14a611aa8e7fdc4e5b0da71c2366eac13a5ef2c6021"},
	{"REC-021", "kafka", "recommendDNS", "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE", rewritten, domain.SafetyCompare, false, "d42dc2d07f1c92f102ec57eb34b03f46055f6234db58b2428a2dc8f2c0117ef1"},
	{"REC-014", "kafka", "recommendHandshakeNotCompleted", "KAFKA_SASL_HANDSHAKE_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "b85308d3c0104692ab7451ad265195d30056df1ae76f407a66aaa3fed7ad3d98"},
	{"REC-015", "kafka", "recommendMechanismNotOffered", "KAFKA_AUTH_MECHANISM_NOT_OFFERED", migrated, domain.SafetyCompare, false, "56a094e5712b9b6b4fa6993357006ae3cc3b3429882334a61e31a8f19c3be0b2"},
	{"REC-016", "kafka", "recommendMetadataNotCompleted", "KAFKA_METADATA_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "fa5996ce13635c053d4aa6399fd384887cceddbfa3c89e77f97ac7fa87bd2185"},
	{"REC-017", "kafka", "recommendPeerVerificationFailed", "KAFKA_PEER_VERIFICATION_FAILED", migrated, domain.SafetyVerify, false, "1f7d3a5490f4dd1911bb8432c7f7faabad36573ef21cf7ddb42a959c67799843"},
	{"REC-022", "kafka", "recommendTCP", "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE", migrated, domain.SafetyVerify, false, "cb6dbe4c0746aebfb3a5b0fd1d9c6c9d655b041baaf3559ea678c6e18d88cdce"},
	{"REC-023", "kafka", "recommendTLS", "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE", migrated, domain.SafetyVerify, false, "0211041efe98637b741aca0e2a02cf4b155dfcccd5675abeb65bdb573793b8db"},
	{"REC-024", "kafka", "recommendUnmeasured", "KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY", alreadyClassified, domain.SafetyObserve, true, "a67d734c884d82e5ea91b29cf26e270d3b856932b000d735e8e8bacefb2d555c"},
	{"REC-025", "kafka", "recommendUnsuitable", "KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE", alreadyClassified, domain.SafetyCompare, false, "a95c6537b96efcc6b3be4ea7bcbfd50c0a2c16eb39d9aeca5dcedbe97d017d44"},
	{"REC-018", "kafka", "recommendUnsupportedBySvcdoctor", "KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR", migrated, domain.SafetyObserve, false, "32c6387d15ddd075e0a55d467a364212fd7d7a394fcf99523f310f6e5081c8ac"},
	{"REC-019", "kafka", "recommendUnsupportedExchange", "KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR", migrated, domain.SafetyObserve, false, "b21670f42441f422fdf84cea73147bc4725dcb51da58564c72c05a2c857e9f90"},
	{"REC-026", "kafka", "recommendUnusable", "KAFKA_ADVERTISED_ENDPOINT_UNUSABLE", migrated, domain.SafetyObserve, false, "1f95a28c6502e0dabb27bb530f3c9c1e6f6a0a3cc38f36001936d56c48d9ecc4"},
	{"REC-020", "kafka", "recommendVersionRejected", "KAFKA_API_VERSIONS_VERSION_REJECTED", migrated, domain.SafetyCompare, false, "94561a18a30344581347e242faf2dd3a96348f99ff20715ee4ea18fed2d45d1d"},
	{"REC-027", "postgres", "recommendAdmissionContrast", "POSTGRES_ADMISSION_SCOPE", alreadyClassified, domain.SafetyCompare, false, "261cdb49e860a134f24e38f47ba35134a484da8dcf79719fbb4abde5fd5a9215"},
	{"REC-028", "postgres", "recommendAdmissionUnmeasured", "POSTGRES_ADMISSION_SCOPE", alreadyClassified, domain.SafetyObserve, true, "824099066366fddd0df1aa3023a3b4c42b3d9924d17391ebba10cf3bf06f790d"},
	{"REC-029", "postgres", "recommendAuthenticationFailed", "POSTGRES_AUTHENTICATION_FAILED", migrated, domain.SafetyObserve, false, "8e222e9e3aa017e646e4c21b1598d214846e66c2133cbb8303c628d934577302"},
	{"REC-037", "postgres", "recommendConnectionLimitReached", "POSTGRES_CONNECTION_LIMIT_REACHED", alreadyClassified, domain.SafetyCompare, false, "9136b3928c3b83b8af8f9a471f66a41b373b8e8c09f6b68b720cb29da03d577c"},
	{"REC-030", "postgres", "recommendCredentialNotConfigured", "POSTGRES_CREDENTIAL_NOT_CONFIGURED", migrated, domain.SafetyObserve, false, "5235f25384dea21b377783187f5ebd25a0cf2a5dbd8b32c31630960f3330e794"},
	{"REC-031", "postgres", "recommendCredentialWithheld", "POSTGRES_CREDENTIAL_WITHHELD", rewritten, domain.SafetyObserve, false, "01a256bf2770f11da52521d2bdc6baee7ab9fed10b546e297a7e21d05b96401d"},
	{"REC-032", "postgres", "recommendCredentialsRejected", "POSTGRES_CREDENTIALS_REJECTED", migrated, domain.SafetyVerify, false, "6e3355bde0bf167f758d2a472f99a783f061438ea91ef9fca001ac400feef282"},
	{"REC-038", "postgres", "recommendDatabaseConnectDenied", "POSTGRES_DATABASE_CONNECT_DENIED", migrated, domain.SafetyVerify, false, "c7cb4086ece157b4a52213c5b33ff49c17a7bd26e3aa83d932d6329ed0df89a1"},
	{"REC-039", "postgres", "recommendDatabaseNotFound", "POSTGRES_DATABASE_NOT_FOUND", migrated, domain.SafetyVerify, false, "c6424ca86613013e5398ed1396ebc6b358164d8ddf8adc1e1bd06fb7a3d8e270"},
	{"REC-033", "postgres", "recommendMechanismNotOffered", "POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE", migrated, domain.SafetyObserve, false, "def6c5f1828304397dd998231014eaab67da29fa0ff50e691f342132db5054f5"},
	{"REC-034", "postgres", "recommendMechanismUnsupported", "POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE", rewritten, domain.SafetyObserve, false, "3467352d38e4a26adf86b359f23201acb55f92baa870d578e84ffc87a995250c"},
	{"REC-041", "postgres", "recommendNotPermitted", "POSTGRES_CONNECTION_NOT_PERMITTED", migrated, domain.SafetyObserve, false, "d5167a709428e51d70459cec8f7e44f8b91d78455350bc66daa086756ef6e3b5"},
	{"REC-035", "postgres", "recommendPeerVerificationFailed", "POSTGRES_PEER_VERIFICATION_FAILED", migrated, domain.SafetyVerify, false, "e1c125436ba8e30761f35f8863621ecbbcc2d62b8bcb16de66a15c4c294e1525"},
	{"REC-042", "postgres", "recommendSSLNegotiationFailed", "POSTGRES_SSL_NEGOTIATION_FAILED", migrated, domain.SafetyVerify, false, "2eb5002f5c1701a6353d246cb6494e6ef70640895649c7d1c54159d77c87ba07"},
	{"REC-040", "postgres", "recommendSessionEstablishmentFailed", "POSTGRES_SESSION_ESTABLISHMENT_FAILED", migrated, domain.SafetyObserve, false, "214d7c8f88ce6e8a173c848a8df089d98431d9a71e4797beca878b50e7b00415"},
	{"REC-044", "postgres", "recommendStartupFailed", "POSTGRES_STARTUP_FAILED", migrated, domain.SafetyObserve, false, "87398f2d21b992e59029ed8f0f338c0777bdd5a0c3419f0745d74cbe9262e903"},
	{"REC-045", "postgres", "recommendTLSCertificateNotValidNow", "POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW", migrated, domain.SafetyCompare, false, "4212ffa7e02fe4c01fc665fc415842f3fd01c7ebed767c636d1daf99d78822d8"},
	{"REC-046", "postgres", "recommendTLSChainNotTrusted", "POSTGRES_TLS_CHAIN_NOT_TRUSTED", migrated, domain.SafetyCompare, false, "dcb463d074c98599653bf2efecf7762a18459421421ed0e8753e480755fff351"},
	{"REC-043", "postgres", "recommendTLSDeclined", "POSTGRES_TLS_DECLINED", migrated, domain.SafetyObserve, false, "a0bf304b184e1c3d715908a43a0cf72ed7aea3c0f595ac2d02f0f5b85f52b13c"},
	{"REC-047", "postgres", "recommendTLSHandshakeFailed", "POSTGRES_TLS_HANDSHAKE_FAILED", migrated, domain.SafetyObserve, false, "69d10fe000fff4bfb9395919c22ae1de5d6c16e0ee62e074cababaaa5265ba6a"},
	{"REC-048", "postgres", "recommendTLSIdentityMismatch", "POSTGRES_TLS_IDENTITY_MISMATCH", migrated, domain.SafetyCompare, false, "1fbacb641dd84d20b01ecb0a9a24958906854284845a012aa6ca84bd3a0f9a06"},
	{"REC-049", "postgres", "recommendTLSUpgradeNotHonored", "POSTGRES_TLS_UPGRADE_NOT_HONORED", migrated, domain.SafetyObserve, false, "46a1b34057abcdabbc13ce3a11358541e6e6b7649372a6196c0fe93c2f5332c5"},
	{"REC-036", "postgres", "recommendUnsupportedBySvcdoctor", "POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR", rewritten, domain.SafetyObserve, false, "a06117c5370f7fafb9a895ab47cf03aab858b58a7f47bf263078a01b5eb5ac9e"},
	{"REC-050", "redis", "recommendAuthenticationNotCompleted", "REDIS_AUTHENTICATION_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "bb806efb10e5f56e5ca5f7ccb3b6a050a79550982604561634643e3b1afb6a2a"},
	{"REC-055", "redis", "recommendCommandNotPermitted", "REDIS_COMMAND_NOT_PERMITTED", rewritten, domain.SafetyVerify, false, "74820b09be4fac870a09e0d501f4d7e23b23e549a1b68d32e131b6c693f94e63"},
	{"REC-051", "redis", "recommendCredentialNotConfigured", "REDIS_CREDENTIAL_NOT_CONFIGURED", migrated, domain.SafetyObserve, false, "bf0fa792da942849cb68c041af2e47b54d179595c263746d26684ebce2eb7aa3"},
	{"REC-052", "redis", "recommendCredentialWithheld", "REDIS_CREDENTIAL_WITHHELD", rewritten, domain.SafetyObserve, false, "bbd2f6dfb677a7cc411cc7a9a5bd1a6b603f5ee603cbda48e05c6f7121928b44"},
	{"REC-053", "redis", "recommendCredentialsRejected", "REDIS_CREDENTIALS_REJECTED", migrated, domain.SafetyVerify, false, "aee13c1683067ebc091c10f41ae2352b7165c890dd8c2314d4647cc6d591d01b"},
	{"REC-056", "redis", "recommendEndpointNotServing", "REDIS_ENDPOINT_NOT_SERVING", migrated, domain.SafetyObserve, false, "f71047dd5d9d917c35e376cd2db90c3ae2688ba17f68c53df967e05d1fbc9646"},
	{"REC-057", "redis", "recommendPingNotCompleted", "REDIS_PING_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "19baef77d1cd6867dae25de3bbbbed1b024da6418e9a9cca4c09a89d4671e7cc"},
	{"REC-054", "redis", "recommendProtocolNotEstablished", "REDIS_PROTOCOL_NOT_ESTABLISHED", migrated, domain.SafetyObserve, false, "6e2b25c2dbf4b39f2bc57d0ccf870139baf159c32e3b02058c1f4c39cf2297ea"},
	{"REC-058", "redis", "recommendSentinel", "REDIS_ENDPOINT_IS_SENTINEL", migrated, domain.SafetyObserve, false, "f0039cfe1cbcf8b02dbc68be9132f51fee273dfafea150933215d964e788075b"},
	{"REC-059", "rabbitmq", "recommendAuthNotCompleted", "RABBITMQ_AUTHENTICATION_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "07f6a88be512848b197f044dd1d7119f03c2d23de481593b1fe1946b1289d641"},
	{"REC-060", "rabbitmq", "recommendAuthUnsupported", "RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR", migrated, domain.SafetyCompare, false, "2e99d6f64572e9898a7a973c48aa774265a9f610d3dfcdbc70026024ce1d28ac"},
	{"REC-065", "rabbitmq", "recommendConnectionNotEstablished", "RABBITMQ_CONNECTION_NOT_ESTABLISHED", migrated, domain.SafetyObserve, false, "58abca4d5dbf65ec91170a1227701acf65b1aba846c08f7f6fe51545321ddc38"},
	{"REC-066", "rabbitmq", "recommendConnectionNotPermitted", "RABBITMQ_CONNECTION_NOT_PERMITTED", migrated, domain.SafetyObserve, false, "a09e3d44a903e2e85396f201c053e534747d88fcf2ff2ec855558cd6e2c90e0e"},
	{"REC-061", "rabbitmq", "recommendCredentialNotConfigured", "RABBITMQ_CREDENTIAL_NOT_CONFIGURED", migrated, domain.SafetyObserve, false, "8aec77f663771d798e2ebf8ebfed187cd958d18c919fc697026acb285ef38a34"},
	{"REC-062", "rabbitmq", "recommendCredentialWithheld", "RABBITMQ_CREDENTIAL_WITHHELD", migrated, domain.SafetyObserve, false, "7260febadc7c611af9aa898ec8b324c90ff5fff1d54d09ed13f359d291bc2936"},
	{"REC-063", "rabbitmq", "recommendCredentialsRejected", "RABBITMQ_CREDENTIALS_REJECTED", migrated, domain.SafetyVerify, false, "7235afe1d433bf1e67d56aa06e1a2573b37d730c89f141dd7b81abe5957e2628"},
	{"REC-064", "rabbitmq", "recommendMechanismNotOffered", "RABBITMQ_AUTH_MECHANISM_NOT_OFFERED", rewritten, domain.SafetyObserve, false, "3bc29c0cb8b202c9f289f70de5a822e055122e70ad1dff685e6139abdf97c8a6"},
	{"REC-069", "rabbitmq", "recommendStartNotCompleted", "RABBITMQ_CONNECTION_START_NOT_COMPLETED", migrated, domain.SafetyVerify, false, "5eaceecb699dfb2f1065abbcb308c3863397441c40e0732f7d3d3a64fdc717f8"},
	{"REC-067", "rabbitmq", "recommendVHostAccessRefused", "RABBITMQ_VHOST_ACCESS_REFUSED", rewritten, domain.SafetyVerify, false, "02c6589529dbf97df62e20689ae6a8234c761fa6540f16d933cd7c823c694737"},
	{"REC-068", "rabbitmq", "recommendVHostNotFound", "RABBITMQ_VHOST_NOT_FOUND", migrated, domain.SafetyVerify, false, "1f34aa8292d30f1b6dcbf0ef7142361a6024bf16749a510b74e140ed22151936"},
	{"REC-070", "kubernetes", "recommendAPIAccessDenied", "KUBERNETES_API_ACCESS_DENIED", alreadyClassified, domain.SafetyVerify, false, "792d90b7ad50e8cabbfac91d1ecccc934b0298c377bde66365ec486bdf7c7cdc"},
	{"REC-072", "kubernetes", "recommendNoReadyEndpoint", "KUBERNETES_SERVICE_NO_READY_ENDPOINT", alreadyClassified, domain.SafetyCompare, false, "a4960457d8fd977cabc3c95ae833225a8eec14352c6545f17784bd96ea43321a"},
	{"REC-073", "kubernetes", "recommendSelectsNoPods", "KUBERNETES_SERVICE_SELECTS_NO_PODS", alreadyClassified, domain.SafetyCompare, false, "09c7d8f6f0537140fc751cacda62f425e68e1650727bfe30bbe37a22a3d824e2"},
	{"REC-071", "kubernetes", "recommendServiceNotFound", "KUBERNETES_SERVICE_NOT_FOUND", alreadyClassified, domain.SafetyVerify, false, "78be2e25d476a382ebc93909963591e5da458845354079796e440800c4119368"},
}

// productionDiagnosisPackages is the boundary this file's guards scan.
//
// It is derived rather than listed, from allProductionPackages, so a new rule
// package cannot escape the guards by not being named here.
func productionDiagnosisPackages(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pkg := range allProductionPackages(t) {
		if strings.HasPrefix(pkg, genericDiagnosisPackage) {
			out = append(out, pkg)
		}
	}
	if len(out) < 6 {
		t.Fatalf("found %d diagnosis packages, want at least 6; the scan would be "+
			"nearly vacuous", len(out))
	}
	return out
}

// recommendationConstants returns every recommend<Name> constant the production
// diagnosis tree declares, keyed "pkg/const", with its assembled text.
//
// Concatenated parts are joined in source order, for the reason
// TestDIAG036EveryProducedRecommendationIsAlreadySafe gives: half a sentence
// would be compared against a rule about whole ones.
func recommendationConstants(t *testing.T) map[string]string {
	t.Helper()

	out := map[string]string{}
	for _, pkg := range productionDiagnosisPackages(t) {
		leaf := path.Base(pkg)
		for _, file := range productionFilesIn(t, pkg) {
			ast.Inspect(parseFile(t, file), func(node ast.Node) bool {
				spec, ok := node.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range spec.Names {
					if !strings.HasPrefix(name.Name, "recommend") ||
						len(name.Name) < 10 || i >= len(spec.Values) {
						continue
					}
					if text, ok := joinedStringLiteral(spec.Values[i]); ok {
						out[leaf+"/"+name.Name] = text
					}
				}
				return true
			})
		}
	}
	return out
}

// TestEveryRecommendationConstantIsAccountedFor is the completeness guard, and it
// is what lets every other test in this file be a table.
//
// It fails in both directions: a new production recommendation that nobody
// classified, and a table row for a constant that no longer exists.
func TestEveryRecommendationConstantIsAccountedFor(t *testing.T) {
	found := recommendationConstants(t)
	if len(found) == 0 {
		t.Fatal("no recommendation constant was found at all; this guard would pass vacuously")
	}

	table := map[string]recommendationRecord{}
	for _, r := range recommendationCorpus {
		key := r.pkg + "/" + r.constant
		if _, dup := table[key]; dup {
			t.Fatalf("%s appears twice in the corpus table; one constant carries one "+
				"classification (ADR 0097 section 2.3)", key)
		}
		table[key] = r
	}

	for key := range found {
		if _, ok := table[key]; !ok {
			t.Errorf("%s is a production recommendation with no entry in "+
				"recommendationCorpus.\n\n"+
				"ADR 0097 section 2.1: a production rule may not decline to classify its "+
				"own advice. Add the row with its kind, safety class and collectability, "+
				"or route the constant through the package's advise helper.", key)
		}
	}
	for key := range table {
		if _, ok := found[key]; !ok {
			t.Errorf("recommendationCorpus names %s, which the production tree no longer "+
				"declares; delete the row in the change that removed it", key)
		}
	}

	var byGroup [3]int
	for _, r := range recommendationCorpus {
		byGroup[r.group]++
	}
	for _, want := range []struct {
		group migrationGroup
		n     int
		what  string
	}{
		{migrated, 55, "Phase 13.1B migrated"},
		{alreadyClassified, 9, "already classified before 13.1B"},
		{rewritten, 9, "Phase 13.1C rewritten and classified"},
	} {
		if got := byGroup[want.group]; got != want.n {
			t.Errorf("%d recommendations are %s, want %d", got, want.what, want.n)
		}
	}
	if total := len(recommendationCorpus); total != 73 {
		t.Errorf("the corpus holds %d recommendations, want 73", total)
	}
	// **Every group is structured since Phase 13.1C.** There is no fourth group
	// and no unclassified one, which is the invariant ADR 0097 section 2.1 was
	// written to reach; TestNoProductionRuleBuildsAnUnclassifiedRecommendation is
	// the structural half of the same statement.
	structured := byGroup[migrated] + byGroup[alreadyClassified] + byGroup[rewritten]
	if structured != 73 {
		t.Errorf("%d recommendations are structured, want 73 — all of them", structured)
	}
	t.Logf("73 recommendations, all structured: %d migrated in 13.1B, %d earlier, "+
		"%d rewritten and classified in 13.1C", byGroup[migrated],
		byGroup[alreadyClassified], byGroup[rewritten])
}

// TestMigratedRecommendationActionTextIsFrozen is the proof that Phase 13.1B
// changed metadata and not meaning.
//
// Byte-for-byte, over all 64 previously-unclassified actions and the 9 that were
// already classified — the whole corpus, because the claim is about the whole
// corpus.
func TestMigratedRecommendationActionTextIsFrozen(t *testing.T) {
	found := recommendationConstants(t)
	if len(found) == 0 {
		t.Fatal("no recommendation constant was found; this guard would pass vacuously")
	}

	var checked int
	for _, r := range recommendationCorpus {
		text, ok := found[r.pkg+"/"+r.constant]
		if !ok {
			continue // reported by the completeness guard
		}
		sum := sha256.Sum256([]byte(text))
		if got := hex.EncodeToString(sum[:]); got != r.actionSHA256 {
			t.Errorf("%s (%s/%s) action text changed.\n\n"+
				"want sha256 %s\ngot  sha256 %s\n\ntext now: %q\n\n"+
				"Phase 13.1B is metadata-only: no capitalization, punctuation, whitespace "+
				"or wording may move. A deliberate rewording belongs to the phase that "+
				"reviews the sentence, and it moves this hash in the same change.",
				r.rec, r.pkg, r.constant, r.actionSHA256, got, text)
		}
		checked++
	}
	if checked != 73 {
		t.Errorf("%d action texts were checked, want 73", checked)
	}
	t.Logf("%d action texts checked against frozen digests", checked)
}

// TestEveryMigratedRecommendationSurvivesAdmission is the silent-drop defense.
//
// `diagnosis.Recommend` returns nil on any error — an invalid kind/safety pair, a
// blank rationale, an action the text validator refuses, a confidence gate
// refusal. A misclassification therefore does not fail the build; it deletes the
// recommendation from the report. This constructs every classified row through
// the same function production uses and requires one recommendation back.
func TestEveryMigratedRecommendationSurvivesAdmission(t *testing.T) {
	found := recommendationConstants(t)
	var admitted int

	for _, r := range recommendationCorpus {
		text, ok := found[r.pkg+"/"+r.constant]
		if !ok {
			continue // reported by the completeness guard
		}
		t.Run(r.rec, func(t *testing.T) {
			got := diagnosis.Recommend(diagnosis.AdviceInput{
				Kind:   diagnosis.AdviceKindNextEvidence,
				Safety: r.safety,
				Action: text,
				// Non-empty and deterministic. The production rationale is a
				// package constant; what is under test here is that the kind,
				// safety class and action survive admission, and a blank
				// rationale would fail for its own reason and mask that.
				Rationale:       "Admission check for " + r.rec + ".",
				SelfCollectable: r.selfCollectable,
			}, domain.FindingKindConfirmed, domain.ConfidenceHigh)

			if len(got) != 1 {
				t.Fatalf("%s produced %d recommendations, want 1; diagnosis.Recommend "+
					"swallows the error and returns nil, so this is a classification "+
					"the model refuses and a recommendation that would vanish from "+
					"the report", r.rec, len(got))
			}
			rec := got[0]
			if !rec.Classified() {
				t.Errorf("%s came back unclassified", r.rec)
			}
			if rec.Kind() != domain.RecommendationKindNextEvidence {
				t.Errorf("%s kind = %s, want NEXT_EVIDENCE", r.rec, rec.Kind())
			}
			if rec.Safety() != r.safety {
				t.Errorf("%s safety = %s, want %s", r.rec, rec.Safety(), r.safety)
			}
			if rec.SelfCollectable() != r.selfCollectable {
				t.Errorf("%s selfCollectable = %v, want %v",
					r.rec, rec.SelfCollectable(), r.selfCollectable)
			}
			if rec.Action() != text {
				t.Errorf("%s action changed in construction", r.rec)
			}
			if strings.TrimSpace(rec.Rationale()) == "" {
				t.Errorf("%s carries no rationale", r.rec)
			}
		})
		admitted++
	}
	if admitted != 73 {
		t.Errorf("%d classified recommendations were admitted, want 73 — every one in "+
			"the corpus, since Phase 13.1C left none unclassified", admitted)
	}
	t.Logf("%d classified recommendations admitted, 0 silently dropped", admitted)
}

// TestNoProductionRecommendationIsARemediation keeps ADR 0097 section 2.2.
//
// REMEDIATION stays unreachable. The five recommendations that are remediations
// in substance are rewritten by Phase 13.1C rather than promoted, so no
// production rule may name the kind at all.
func TestNoProductionRecommendationIsARemediation(t *testing.T) {
	var scanned int
	for _, pkg := range productionDiagnosisPackages(t) {
		// The generic core is excluded, and the exclusion is the boundary rather
		// than an exemption: internal/diagnosis owns the vocabulary and the gate,
		// so it has to be able to *name* the kind it refuses — AdmitAdvice's whole
		// job is to reject a REMEDIATION on weak evidence. What may not name it is
		// a rule, which is what produces advice.
		if pkg == genericDiagnosisPackage {
			continue
		}
		scanned++
		for _, file := range productionFilesIn(t, pkg) {
			for _, name := range identifiersUsed(t, file) {
				if name == "AdviceKindRemediation" || name == "RecommendationKindRemediation" {
					t.Errorf("%s names %s.\n\n"+
						"ADR 0097 section 2.2: proving a condition does not authorize a "+
						"policy, so REMEDIATION has no producer. Activating it is a new "+
						"record with its own security review.", file, name)
				}
			}
		}
	}
	if scanned < 6 {
		t.Fatalf("only %d rule packages were scanned, want at least 6; the guard would "+
			"be nearly vacuous", scanned)
	}

	// And the same statement through the corpus, so the two readings are together.
	for _, r := range recommendationCorpus {
		if r.safety == domain.SafetyConfigChange {
			t.Errorf("%s is classified CONFIG_CHANGE; no production recommendation is, "+
				"and a target-changing class needs its own ADR and security review "+
				"(ADR 0097 section 7)", r.rec)
		}
	}
}

// TestClassifiedRecommendationsUseOnlyTheReadOnlySafetyClasses pins the reachable
// safety set.
//
// Three of the seven, and the other four for different reasons: CONFIG_CHANGE is
// producible and unused because §8.2 of the freeze rewrites its candidates, and
// RESTART, DISRUPTIVE and SECURITY_WEAKENING are refused by Producible() itself.
func TestClassifiedRecommendationsUseOnlyTheReadOnlySafetyClasses(t *testing.T) {
	for _, r := range recommendationCorpus {
		if !r.safety.ChangesNothing() {
			t.Errorf("%s is classified %s, which changes the target; every classified "+
				"recommendation in this corpus is NEXT_EVIDENCE and must therefore be "+
				"OBSERVE, VERIFY or COMPARE (ADR 0082 section 2.4)", r.rec, r.safety)
		}
	}
	for _, unreachable := range []domain.SafetyClass{
		domain.SafetyRestart, domain.SafetyDisruptive, domain.SafetySecurityWeakening,
	} {
		if unreachable.Producible() {
			t.Errorf("%s became producible; ADR 0097 section 2.2 keeps all three "+
				"unreachable", unreachable)
		}
	}
}

// TestNoProductionRuleBuildsAnUnclassifiedRecommendation is the permanent
// invariant ADR 0097 section 2.1 exists to reach, and Phase 13.1C is where it
// became provable.
//
// # What replaced what
//
// Phase 13.1B left a shrink-only allowlist: five production construction sites in
// four packages, each naming the Phase 13.1C recommendations it served, with the
// package count and the nine identifiers pinned so a tenth exemption could not
// arrive unnoticed. That machinery existed to make a temporary state safe. The
// state is over — all nine sentences were reviewed, rewritten and classified —
// so the allowlist is **deleted** rather than emptied. A guard that reads
// "expected legacy producers = []" invites someone to append to it; one that
// proves zero directly does not.
//
// # Why the scan is structural
//
// It walks every production file in every package under internal/diagnosis,
// derived from allProductionPackages rather than from a remembered list, so a new
// rule package cannot escape it. It matches the **call expression**
// domain.NewRecommendation in an AST, not a substring, so a mention in a comment
// or a doc string is not a finding and a helper that wraps the constructor under
// another name still is — the wrapper has to call it somewhere.
//
// domain.NewRecommendation itself is kept: internal/security/redaction rebuilds
// an unclassified recommendation through it, and the domain type still admits
// one. What may not happen is a *rule* building one.
func TestNoProductionRuleBuildsAnUnclassifiedRecommendation(t *testing.T) {
	packages := productionDiagnosisPackages(t)
	if len(packages) < 6 {
		t.Fatalf("only %d production rule packages were found, want at least 6; the "+
			"scan would be nearly vacuous", len(packages))
	}

	var scanned int
	for _, pkg := range packages {
		files := productionFilesIn(t, pkg)
		if len(files) == 0 {
			t.Errorf("%s yielded no production file; the scan of it asserts nothing", pkg)
		}
		for _, file := range files {
			scanned++
			if callsUnclassifiedConstructor(t, file) {
				t.Errorf("%s builds an unclassified recommendation.\n\n"+
					"ADR 0097 section 2.1: a production rule may not decline to classify "+
					"its own advice, and since Phase 13.1C there is no exemption list to "+
					"add it to. Route it through the package's advise helper with a "+
					"safety class and a rationale.\n\n"+
					"If the sentence genuinely cannot be classified as NEXT_EVIDENCE with "+
					"OBSERVE, VERIFY or COMPARE, that is evidence it should be removed "+
					"rather than that the taxonomy should widen.", file)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no production file was scanned at all; this guard would pass vacuously")
	}
	t.Logf("%d production files across %d rule packages build no unclassified "+
		"recommendation", scanned, len(packages))
}

// TestTheUnclassifiedConstructorScanIsNotVacuous is the companion the invariant
// above needs.
//
// Every assertion in it is an absence, so it would pass on an empty scan, on a
// broken matcher, or on a matcher that looks for the wrong thing. This drives the
// same detector over source that *does* call the constructor and requires a hit —
// and over source that only mentions it in prose and requires none, because a
// substring scan would fail that second half.
func TestTheUnclassifiedConstructorScanIsNotVacuous(t *testing.T) {
	dir := t.TempDir()

	positive := filepath.Join(dir, "positive.go")
	writeFixture(t, positive, `package p

import "github.com/hakanaltindag/svcdoctor/internal/domain"

func legacy(action string) []domain.Recommendation {
	r, err := domain.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []domain.Recommendation{r}
}
`)
	if !callsUnclassifiedConstructor(t, positive) {
		t.Error("the detector missed a real domain.NewRecommendation call site, so the " +
			"zero-legacy invariant proves nothing")
	}

	// The aliased form, which the Phase 13.1C mutation suite planted and which
	// survived the first run: the detector was matching the identifier "domain"
	// rather than the package it names.
	aliased := filepath.Join(dir, "aliased.go")
	writeFixture(t, aliased, `package p

import dom "github.com/hakanaltindag/svcdoctor/internal/domain"

func legacy(action string) []dom.Recommendation {
	r, err := dom.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []dom.Recommendation{r}
}
`)
	if !callsUnclassifiedConstructor(t, aliased) {
		t.Error("the detector missed domain.NewRecommendation reached through an import " +
			"alias, so renaming an import would silence the zero-legacy invariant")
	}

	// And a selector of the same name on a package that is not the domain, which
	// must not fire: the match is on the import path, not on the method name.
	lookalike := filepath.Join(dir, "lookalike.go")
	writeFixture(t, lookalike, `package p

import domain "github.com/hakanaltindag/svcdoctor/internal/diagnosis"

func notTheConstructor() { domain.NewRecommendation("x") }
`)
	if callsUnclassifiedConstructor(t, lookalike) {
		t.Error("the detector fired on a NewRecommendation selector belonging to another " +
			"package, so it matches the method name rather than the package")
	}

	negative := filepath.Join(dir, "negative.go")
	writeFixture(t, negative, `package p

// domain.NewRecommendation is named here in prose only. Phase 13.1C deleted the
// last production caller; this comment must not read as one.
const note = "domain.NewRecommendation(action)"
`)
	if callsUnclassifiedConstructor(t, negative) {
		t.Error("the detector fired on a comment and a string literal, which makes it a " +
			"substring scan rather than an AST one; it would block a truthful comment " +
			"and could be silenced by rewording")
	}
}

// writeFixture writes one temporary Go file for the non-vacuity proof.
func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestTheRecommendationClassificationGuardsCanFail proves the guards above are
// load-bearing.
func TestTheRecommendationClassificationGuardsCanFail(t *testing.T) {
	t.Run("the constant scan finds the real corpus", func(t *testing.T) {
		found := recommendationConstants(t)
		if len(found) != 73 {
			t.Fatalf("the scan found %d recommendation constants, want 73; every table "+
				"guard in this file is only as complete as this number", len(found))
		}
		for _, known := range []string{
			"transport/recommendNameNotResolved",
			"kafka/recommendCredentialWithheld",
			"postgres/recommendNotPermitted",
			"redis/recommendSentinel",
			"rabbitmq/recommendVHostAccessRefused",
			"kubernetes/recommendSelectsNoPods",
		} {
			if _, ok := found[known]; !ok {
				t.Errorf("the scan missed %s, so its package is invisible to these guards",
					known)
			}
		}
	})

	t.Run("a changed action text is detected", func(t *testing.T) {
		sum := sha256.Sum256([]byte("Check that the endpoint accepts connections"))
		if hex.EncodeToString(sum[:]) == recommendationCorpus[0].actionSHA256 {
			t.Error("the frozen digest matches unrelated text; the comparison is not " +
				"discriminating")
		}
	})

	t.Run("an invalid classification is refused by construction", func(t *testing.T) {
		// The exact shape the silent-drop guard exists to catch: next evidence
		// with a class that changes the target.
		got := diagnosis.Recommend(diagnosis.AdviceInput{
			Kind:      diagnosis.AdviceKindNextEvidence,
			Safety:    diagnosis.SafetyConfigChange,
			Action:    "Check the thing the finding names",
			Rationale: "Because the guard must be able to fail.",
		}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
		if len(got) != 0 {
			t.Error("a next-evidence recommendation classified CONFIG_CHANGE was admitted; " +
				"the silent-drop guard would then never fire")
		}
	})

	t.Run("a blank rationale is refused", func(t *testing.T) {
		got := diagnosis.Recommend(diagnosis.AdviceInput{
			Kind:   diagnosis.AdviceKindNextEvidence,
			Safety: diagnosis.SafetyObserve,
			Action: "Check the thing the finding names",
		}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
		if len(got) != 0 {
			t.Error("advice with no rationale was admitted")
		}
	})

	// The legacy scan used to be proved non-vacuous by pointing it at
	// internal/diagnosis/redis, which really did hold two exemptions. Phase 13.1C
	// removed the last caller in the tree, so there is no longer a production file
	// that would make it fire — and a detector with nothing to detect is exactly
	// the vacuity this sub-test existed to refuse. It moved to a synthetic fixture
	// rather than being deleted: TestTheUnclassifiedConstructorScanIsNotVacuous
	// drives the same detector over source that does call the constructor and over
	// source that only names it in prose.
	t.Run("no production file would make the legacy scan fire", func(t *testing.T) {
		for _, pkg := range productionDiagnosisPackages(t) {
			for _, file := range productionFilesIn(t, pkg) {
				if callsUnclassifiedConstructor(t, file) {
					t.Errorf("%s still builds an unclassified recommendation", file)
				}
			}
		}
	})
}

// identifiersUsed returns every identifier and selector-field name one production
// file uses, from its AST.
//
// AST and not text, and the reason is in this file: its own prose names
// REMEDIATION and the unclassified constructor while asserting that no rule may
// use them, so a text scan would report the guard as the violation. Phase 12.2B
// found the same class of defect in a shell-tracing check that matched the
// sentence explaining why it does not trace.
func identifiersUsed(t *testing.T, file string) []string {
	t.Helper()
	var out []string
	ast.Inspect(parseFile(t, file), func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Ident:
			out = append(out, n.Name)
		case *ast.SelectorExpr:
			out = append(out, n.Sel.Name)
		}
		return true
	})
	return out
}

// callsUnclassifiedConstructor reports whether a production file calls
// domain.NewRecommendation, read from the call expressions rather than the bytes.
func callsUnclassifiedConstructor(t *testing.T, file string) bool {
	t.Helper()

	parsed := parseFile(t, file)

	// The local names under which this file can reach the domain package.
	//
	// **Resolved from the import declarations rather than assumed to be
	// "domain".** The Phase 13.1C mutation suite planted `dom
	// "…/internal/domain"` and called `dom.NewRecommendation`, and it survived:
	// the detector was matching the identifier a reader expects instead of the
	// package it names, so renaming the import silenced the phase's load-bearing
	// guard. Nothing about the plant was exotic — this repository already imports
	// packages under an alias in a dozen places, `servicekafka` among them.
	locals := map[string]bool{}
	for _, spec := range parsed.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != domainPackage {
			continue
		}
		switch {
		case spec.Name == nil:
			// The package's own name, which is its last path segment here.
			locals["domain"] = true
		case spec.Name.Name == "_" || spec.Name.Name == ".":
			// A blank import cannot call anything, and a dot import would put
			// NewRecommendation in file scope with no selector at all — which the
			// selector match below cannot see. Treated as a finding rather than
			// ignored, because it is a way to reach the constructor.
			locals[spec.Name.Name] = true
		default:
			locals[spec.Name.Name] = true
		}
	}
	if locals["."] {
		return true
	}

	var found bool
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewRecommendation" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && locals[pkg.Name] {
			found = true
		}
		return true
	})
	return found
}

// domainPackage is the import path that owns the unclassified constructor.
const domainPackage = "github.com/hakanaltindag/svcdoctor/internal/domain"

// The Phase 13.1C semantic closure, as two guards with different jobs.
//
// ADR 0097 section 2.2 and Phase 13.1A section 8: a finding proves a *condition*
// and the evidence that authorizes the condition does not authorize a *policy*.
// Nine recommendations instructed, or could be read as instructing, a change to
// the diagnosed target; each was rewritten as bounded next evidence.
//
// The pin below is the primary proof and the rule after it is supplemental, in
// that order deliberately. A keyword rule cannot decide whether a sentence
// prescribes policy — English is not that tractable, and section 31 of the phase
// brief says so — but it does stop the *specific* prose this phase removed from
// being written again by someone who has not read the record.

// rewrittenActions are the nine Phase 13.1C sentences, byte for byte.
//
// Keyed by package-qualified constant rather than by finding code, because three
// of the nine share a finding code with a recommendation Phase 13.1B had already
// classified, so a code-level pin would assert the wrong thing.
var rewrittenActions = map[string]string{
	"kafka/recommendCredentialWithheld": "Use --tls require with a trusted certificate " +
		"chain, or supply --tls-ca-file, so this broker's identity is verified before a " +
		"credential crosses to it",
	"kafka/recommendDNS": "Compare the name this broker publishes in advertised.listeners " +
		"with the names resolvable from this network position",
	"postgres/recommendCredentialWithheld": "Use --tls require with a trusted certificate " +
		"chain, or supply --tls-ca-file, so this endpoint's identity is verified before a " +
		"password crosses to it",
	"postgres/recommendMechanismUnsupported": "Diagnose this endpoint with a client that " +
		"performs the authentication method it demands",
	"postgres/recommendUnsupportedBySvcdoctor": "Re-run this diagnosis against a role whose " +
		"password is already printable ASCII, or diagnose this endpoint with a client that " +
		"implements the full mechanism",
	"redis/recommendCredentialWithheld": "Use --tls require with a trusted certificate " +
		"chain, or supply --tls-ca-file, so this endpoint's identity is verified before a " +
		"credential is presented",
	"redis/recommendCommandNotPermitted": "Verify whether this identity is intended to run " +
		"PING, or diagnose with an identity that already has it",
	"rabbitmq/recommendMechanismNotOffered": "Diagnose this endpoint with a client that " +
		"implements one of the mechanisms it offers",
	"rabbitmq/recommendVHostAccessRefused": "Verify whether this identity is intended to " +
		"have access to this virtual host, in the broker's own permissions configuration",
}

// retiredTargetMutatingActions are the nine sentences Phase 13.1C removed.
//
// They are quoted here so that reintroducing one is a named failure rather than a
// silent digest mismatch. Five of them would also be refused by the imperative
// rule below; four would not, and that gap is the reason this list exists.
var retiredTargetMutatingActions = map[string]string{
	"Establish verified TLS to this endpoint, or review the trust context this run used, " +
		"then re-run": "REC-012",
	"Check whether the advertised hostname resolves from this vantage point, and what the " +
		"broker publishes in advertised.listeners": "REC-021",
	"Establish a verified TLS channel to this endpoint before presenting a credential, or " +
		"re-run with the transport policy this run is meant to use": "REC-031",
	"Diagnose this endpoint with a client that performs the authentication method it " +
		"demands, or configure a mechanism svcdoctor performs for the role this run used": "REC-034",
	"Re-run against a role whose password is printable ASCII, or diagnose this endpoint " +
		"with a client that implements the full mechanism": "REC-036",
	"Enable TLS for this endpoint and supply the trust material that verifies it, then run " +
		"again": "REC-052",
	"Grant the diagnostic identity permission to run PING, or diagnose with an identity " +
		"that already has it": "REC-055",
	"Enable SASL PLAIN on this endpoint, or diagnose it with a client that implements the " +
		"mechanisms it offers": "REC-064",
	"Grant this user permissions on the virtual host, for example with rabbitmqctl " +
		"set_permissions": "REC-067",
}

// TestTheRewrittenRecommendationsAreTheFrozenOnes is the primary proof.
func TestTheRewrittenRecommendationsAreTheFrozenOnes(t *testing.T) {
	found := recommendationConstants(t)

	for key, want := range rewrittenActions {
		got, ok := found[key]
		if !ok {
			t.Errorf("%s no longer exists, so its Phase 13.1C pin asserts nothing", key)
			continue
		}
		if got != want {
			t.Errorf("%s reads\n  %q\nwant the frozen Phase 13.1C text\n  %q", key, got, want)
		}
	}

	// And the retired prose is gone from the whole corpus, not merely from the
	// nine constants that used to carry it — a rule could reintroduce the
	// sentence under a different name.
	for text, rec := range retiredTargetMutatingActions {
		for key, action := range found {
			if action == text {
				t.Errorf("%s carries %s's retired action %q.\n\n"+
					"Phase 13.1C removed it because it instructs a change to the "+
					"diagnosed target, or reads as one, and the evidence that "+
					"authorizes the finding does not authorize the change "+
					"(ADR 0097 section 2.2).", key, rec, text)
			}
		}
	}
}

// TestNoProductionRecommendationInstructsATargetMutation is the supplemental
// rule, so that a **new** recommendation is refused on the day it is written
// rather than on the day somebody remembers to add a row above.
//
// # Why it reads clause openings and not the whole string
//
// The obvious implementation — does the action contain "change " anywhere —
// has a false positive already in the tree. Kafka's `recommendUnsupportedExchange`
// ends *"this is a gap in svcdoctor rather than something to change on the
// cluster"*, which is a refusal to recommend a change and would be flagged by a
// substring scan. Phase 12.1D found the same class of defect in a fuzz guard that
// matched "clu" inside "the cluster". An imperative instructs only when it opens
// a clause, so that is what this matches.
//
// # Why "establish" is not on the list
//
// It was, and it flagged two correct recommendations — *"…and establish what this
// broker is before presenting the credential again"* — where the verb means
// *determine*, not *set up*. That ambiguity is exactly why REC-012 and REC-031
// had to be rewritten by hand, and it is why a keyword rule cannot be the whole
// proof. Those two are covered by the byte pin above.
func TestNoProductionRecommendationInstructsATargetMutation(t *testing.T) {
	imperatives := []string{
		"change ", "create ", "delete ", "recreate ", "restart ", "scale ",
		"grant ", "revoke ", "edit ", "increase ", "decrease ", "add ",
		"remove ", "apply ", "patch ", "set ", "disable ", "enable ",
		"bind ", "install ", "rotate ", "configure ", "reconfigure ",
		"allow ", "update ", "modify ", "broaden ", "lower ", "turn ",
	}

	found := recommendationConstants(t)
	if len(found) == 0 {
		t.Fatal("no recommendation constant was found; this guard would pass vacuously")
	}
	for key, action := range found {
		for _, clause := range actionClauses(action) {
			for _, imperative := range imperatives {
				if strings.HasPrefix(clause, imperative) {
					t.Errorf("%s recommends %q, whose clause %q opens with the "+
						"imperative %q.\n\n"+
						"Proving a condition does not authorize a policy: the operator's "+
						"ACL, listener, trust and authentication configuration may be "+
						"doing exactly what its author intended. State the observation "+
						"that would settle it (ADR 0097 section 2.2, Phase 13.1A "+
						"section 8.2).", key, action, clause, imperative)
				}
			}
		}
	}
	t.Logf("%d production recommendations instruct no change to the target", len(found))
}

// TestTheTargetMutationRuleCanFail is the non-vacuity proof for the rule above.
//
// Every assertion in it is an absence, so it would pass on an empty corpus or a
// broken matcher. This drives the matcher over the exact prose Phase 13.1C
// removed and requires the refusal, and over the sentence that caused the false
// positive and requires none.
func TestTheTargetMutationRuleCanFail(t *testing.T) {
	mutating := func(action string) bool {
		for _, clause := range actionClauses(action) {
			for _, imperative := range []string{"grant ", "enable ", "configure ", "change "} {
				if strings.HasPrefix(clause, imperative) {
					return true
				}
			}
		}
		return false
	}

	for _, retired := range []string{
		"Grant this user permissions on the virtual host, for example with rabbitmqctl " +
			"set_permissions",
		"Enable SASL PLAIN on this endpoint, or diagnose it with a client that implements " +
			"the mechanisms it offers",
		"Diagnose this endpoint with a client that performs the authentication method it " +
			"demands, or configure a mechanism svcdoctor performs for the role this run used",
	} {
		if !mutating(retired) {
			t.Errorf("the rule admits %q, which Phase 13.1C removed for instructing a "+
				"change to the target", retired)
		}
	}

	// The clause after "or" is reached, not only the first one: REC-034's
	// mutating half was its second clause.
	if !mutating("Do something harmless, or grant the identity a permission") {
		t.Error("the rule reads only the first clause, so an imperative after a comma " +
			"would survive it")
	}

	keep := "Check the referenced evidence for which limit applied; if the endpoint is " +
		"behaving correctly this is a gap in svcdoctor rather than something to change " +
		"on the cluster"
	if mutating(keep) {
		t.Error("the rule refuses a sentence that declines to recommend a change, which " +
			"makes it a substring scan rather than a clause-opening one")
	}
}

// actionClauses splits an action into the clauses a reader takes as separate
// instructions, with a leading conjunction removed.
func actionClauses(action string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(action, func(r rune) bool {
		return r == ',' || r == ';'
	}) {
		clause := strings.ToLower(strings.TrimSpace(part))
		for _, conjunction := range []string{"or ", "and ", "then ", "but "} {
			clause = strings.TrimPrefix(clause, conjunction)
		}
		if clause != "" {
			out = append(out, clause)
		}
	}
	return out
}
