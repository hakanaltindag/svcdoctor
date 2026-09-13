package security_test

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The Phase 13.1B recommendation-classification contract, as a corpus.
//
// ADR 0097 section 2.1: a production diagnosis rule may not decline to classify
// its own advice. Phase 13.1B classified the 55 whose prose Phase 13.1A found
// safe as written and left 9 for Phase 13.1C, so the invariant is enforced with a
// **temporary, shrink-only** allowlist rather than at zero.
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
	// groupS is one of the 9 Phase 13.1C owns: its action instructs or may
	// instruct a change to the target, and it stays unclassified until that
	// sentence is reviewed (Phase 13.1A section 8.3).
	groupS
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
	{"REC-012", "kafka", "recommendCredentialWithheld", "KAFKA_CREDENTIAL_WITHHELD", groupS, 0, false, "37de4ab0b3509ab1ae8fe0b902682dea80062e58e37a5850489e070e21b31421"},
	{"REC-013", "kafka", "recommendCredentialsRejected", "KAFKA_CREDENTIALS_REJECTED", migrated, domain.SafetyVerify, false, "b874815f7c4f98a23892f14a611aa8e7fdc4e5b0da71c2366eac13a5ef2c6021"},
	{"REC-021", "kafka", "recommendDNS", "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE", groupS, 0, false, "66d1a38b463bca9506d508eb8c92101f8d6d79bfc934dd8a1aa118666575ae56"},
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
	{"REC-031", "postgres", "recommendCredentialWithheld", "POSTGRES_CREDENTIAL_WITHHELD", groupS, 0, false, "b5512073b64794b4009cc79d8b7abc7dd682ed721a025af1bd30ee34d0c4bf9a"},
	{"REC-032", "postgres", "recommendCredentialsRejected", "POSTGRES_CREDENTIALS_REJECTED", migrated, domain.SafetyVerify, false, "6e3355bde0bf167f758d2a472f99a783f061438ea91ef9fca001ac400feef282"},
	{"REC-038", "postgres", "recommendDatabaseConnectDenied", "POSTGRES_DATABASE_CONNECT_DENIED", migrated, domain.SafetyVerify, false, "c7cb4086ece157b4a52213c5b33ff49c17a7bd26e3aa83d932d6329ed0df89a1"},
	{"REC-039", "postgres", "recommendDatabaseNotFound", "POSTGRES_DATABASE_NOT_FOUND", migrated, domain.SafetyVerify, false, "c6424ca86613013e5398ed1396ebc6b358164d8ddf8adc1e1bd06fb7a3d8e270"},
	{"REC-033", "postgres", "recommendMechanismNotOffered", "POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE", migrated, domain.SafetyObserve, false, "def6c5f1828304397dd998231014eaab67da29fa0ff50e691f342132db5054f5"},
	{"REC-034", "postgres", "recommendMechanismUnsupported", "POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE", groupS, 0, false, "b39a4345180a01b8a085d3bff6ed0c04e5e9cd32053a7daeb709cf3974561e4a"},
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
	{"REC-036", "postgres", "recommendUnsupportedBySvcdoctor", "POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR", groupS, 0, false, "8fad92a4222b17c4b14ff29cdb5c2adc999a7378de46664272e221054f6c5d6f"},
	{"REC-050", "redis", "recommendAuthenticationNotCompleted", "REDIS_AUTHENTICATION_NOT_COMPLETED", migrated, domain.SafetyObserve, false, "bb806efb10e5f56e5ca5f7ccb3b6a050a79550982604561634643e3b1afb6a2a"},
	{"REC-055", "redis", "recommendCommandNotPermitted", "REDIS_COMMAND_NOT_PERMITTED", groupS, 0, false, "5c4be2b6de71ab59ef9b7327ec4b98983a4bd33f6fff6e00be18428b12d211e7"},
	{"REC-051", "redis", "recommendCredentialNotConfigured", "REDIS_CREDENTIAL_NOT_CONFIGURED", migrated, domain.SafetyObserve, false, "bf0fa792da942849cb68c041af2e47b54d179595c263746d26684ebce2eb7aa3"},
	{"REC-052", "redis", "recommendCredentialWithheld", "REDIS_CREDENTIAL_WITHHELD", groupS, 0, false, "764c84d22890a879bf8e098e3b0e3c17c7db164b4d17f07ae6a5d4998ad9de23"},
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
	{"REC-064", "rabbitmq", "recommendMechanismNotOffered", "RABBITMQ_AUTH_MECHANISM_NOT_OFFERED", groupS, 0, false, "9242986373f48aba2c61e26e1e6041eb0eb14137bc7badeb3f54cabf2c77a01a"},
	{"REC-069", "rabbitmq", "recommendStartNotCompleted", "RABBITMQ_CONNECTION_START_NOT_COMPLETED", migrated, domain.SafetyVerify, false, "5eaceecb699dfb2f1065abbcb308c3863397441c40e0732f7d3d3a64fdc717f8"},
	{"REC-067", "rabbitmq", "recommendVHostAccessRefused", "RABBITMQ_VHOST_ACCESS_REFUSED", groupS, 0, false, "fe396c79ed8b2a2fb1e647277d5a4914778d7573af7729e9c00217730c3356a1"},
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
		{groupS, 9, "deferred to Phase 13.1C"},
	} {
		if got := byGroup[want.group]; got != want.n {
			t.Errorf("%d recommendations are %s, want %d", got, want.what, want.n)
		}
	}
	if total := len(recommendationCorpus); total != 73 {
		t.Errorf("the corpus holds %d recommendations, want 73", total)
	}
	structured := byGroup[migrated] + byGroup[alreadyClassified]
	if structured != 64 {
		t.Errorf("%d recommendations are structured, want 64", structured)
	}
	t.Logf("73 recommendations: %d structured (%d migrated in 13.1B, %d earlier), "+
		"%d deferred to 13.1C", structured, byGroup[migrated],
		byGroup[alreadyClassified], byGroup[groupS])
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
		if r.group == groupS {
			continue
		}
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
	if admitted != 64 {
		t.Errorf("%d classified recommendations were admitted, want 64", admitted)
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
		if r.group != groupS && r.safety == domain.SafetyConfigChange {
			t.Errorf("%s is classified CONFIG_CHANGE; none of the 55 was, and a "+
				"target-changing class needs the review Phase 13.1C owns", r.rec)
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
		if r.group == groupS {
			if r.safety != domain.SafetyUnspecified {
				t.Errorf("%s is deferred to Phase 13.1C but the corpus gives it safety %s; "+
					"an unclassified recommendation carries none", r.rec, r.safety)
			}
			continue
		}
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

// legacyRecommendationSites are the production functions still permitted to build
// an unclassified recommendation, and the Phase 13.1C recommendations each serves.
//
// **Shrink-only.** The size is pinned below so a tenth exemption cannot arrive
// without a deliberate edit and a written reason in the same change, which is the
// friction the hypothesis-exemption list used before this one replaced it.
var legacyRecommendationSites = map[string]string{
	"internal/diagnosis/transport": "",
	"internal/diagnosis/kafka": "REC-012 KAFKA_CREDENTIAL_WITHHELD (claim.recommendations, " +
		"SafetyUnspecified branch) and REC-021 KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE's DNS " +
		"sentence (recommendationFor, LayerDNS)",
	"internal/diagnosis/postgres": "REC-031 POSTGRES_CREDENTIAL_WITHHELD, REC-034 " +
		"POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE's second clause (mechanismAdvice, " +
		"SafetyUnspecified) and REC-036 POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR",
	"internal/diagnosis/redis": "REC-052 REDIS_CREDENTIAL_WITHHELD and REC-055 " +
		"REDIS_COMMAND_NOT_PERMITTED",
	"internal/diagnosis/rabbitmq": "REC-064 RABBITMQ_AUTH_MECHANISM_NOT_OFFERED and REC-067 " +
		"RABBITMQ_VHOST_ACCESS_REFUSED",
	"internal/diagnosis/kubernetes": "",
}

// TestLegacyRecommendationConstructionIsBoundedToTheNine is the temporary
// invariant ADR 0097 section 2.1 leaves for Phase 13.1C to close at zero.
//
// It scans the actual production boundary rather than a remembered list of files:
// every package that calls domain.NewRecommendation must be one whose allowlist
// entry names the Phase 13.1C recommendations it serves, and a package with an
// empty entry may not call it at all.
func TestLegacyRecommendationConstructionIsBoundedToTheNine(t *testing.T) {
	callers := map[string][]string{}
	for _, pkg := range productionDiagnosisPackages(t) {
		for _, file := range productionFilesIn(t, pkg) {
			if callsUnclassifiedConstructor(t, file) {
				callers[pkg] = append(callers[pkg], path.Base(file))
			}
		}
	}
	if len(callers) == 0 {
		t.Fatal("no production package builds an unclassified recommendation, so either " +
			"Phase 13.1C has landed and this guard and its allowlist should be deleted " +
			"together, or the scan matched nothing and is vacuous")
	}

	for pkg, files := range callers {
		reason, listed := legacyRecommendationSites[pkg]
		switch {
		case !listed:
			t.Errorf("%s builds an unclassified recommendation in %v and is not in "+
				"legacyRecommendationSites.\n\n"+
				"ADR 0097 section 2.1 forbids a production rule from declining to "+
				"classify its own advice. Route it through the package's advise helper, "+
				"or — if the sentence genuinely needs review first — add the exemption "+
				"and move the pinned count in the same change.", pkg, files)
		case reason == "":
			t.Errorf("%s builds an unclassified recommendation in %v, and its allowlist "+
				"entry names no Phase 13.1C recommendation; the package was fully "+
				"migrated and must stay that way", pkg, files)
		}
	}

	var exempt int
	for _, reason := range legacyRecommendationSites {
		if reason != "" {
			exempt++
		}
	}
	const wantExemptPackages = 4
	if exempt != wantExemptPackages {
		t.Errorf("%d packages hold a legacy exemption, want %d.\n\n"+
			"The list is shrink-only: Phase 13.1C removes entries as it rewrites the "+
			"sentences, and a new one is a production rule declining to classify its own "+
			"advice.", exempt, wantExemptPackages)
	}

	// The nine, named individually, so the allowlist cannot be broadened by
	// rewording a reason.
	var named int
	for _, reason := range legacyRecommendationSites {
		named += len(regexp.MustCompile(`REC-\d{3}`).FindAllString(reason, -1))
	}
	if named != 9 {
		t.Errorf("the allowlist names %d REC identifiers, want exactly the 9 Phase 13.1C "+
			"owns", named)
	}

	// And the nine it names are the nine the corpus marks deferred.
	var deferred []string
	for _, r := range recommendationCorpus {
		if r.group == groupS {
			deferred = append(deferred, r.rec)
		}
	}
	sort.Strings(deferred)
	var allowed []string
	for _, reason := range legacyRecommendationSites {
		allowed = append(allowed, regexp.MustCompile(`REC-\d{3}`).FindAllString(reason, -1)...)
	}
	sort.Strings(allowed)
	if strings.Join(deferred, ",") != strings.Join(allowed, ",") {
		t.Errorf("the allowlist and the corpus disagree about which recommendations are "+
			"deferred.\n\ncorpus:    %v\nallowlist: %v", deferred, allowed)
	}
	t.Logf("%d packages hold a legacy exemption covering %s", exempt, allowed)
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

	t.Run("the legacy scan sees a real caller", func(t *testing.T) {
		var found bool
		for _, file := range productionFilesIn(t, "internal/diagnosis/redis") {
			if callsUnclassifiedConstructor(t, file) {
				found = true
			}
		}
		if !found {
			t.Error("the legacy scan finds no caller in internal/diagnosis/redis, which " +
				"holds two Phase 13.1C exemptions; the boundary guard is vacuous")
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
	var found bool
	ast.Inspect(parseFile(t, file), func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewRecommendation" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "domain" {
			found = true
		}
		return true
	})
	return found
}
