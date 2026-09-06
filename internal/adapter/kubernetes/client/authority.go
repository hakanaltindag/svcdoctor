package client

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	discoveryv1client "k8s.io/client-go/kubernetes/typed/discovery/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// InClusterHost is the DNS name of the Kubernetes API Service inside a cluster.
//
// It is the **logical endpoint** an in-cluster run is about, and it is a real
// name rather than an invention: every cluster publishes its API server as the
// `kubernetes` Service in the `default` namespace, and this is that Service's
// fully qualified name.
//
// The connection is made to whatever KUBERNETES_SERVICE_HOST names, which is
// that Service's cluster IP. Binding the credential to the name while connecting
// to the address is the same logical-endpoint rule every other service in
// svcdoctor already follows: one lookup producing an address does not produce a
// second authority (ADR 0028 section 2).
//
// It is also the identity TLS verifies against, which is stronger than trusting
// whichever SAN happens to cover the cluster IP.
const InClusterHost = "kubernetes.default.svc"

// InClusterPort is the port the API Service publishes.
const InClusterPort uint16 = 443

// clientcmdLoad is the one call into clientcmd, and it is a parse.
//
// A variable rather than a direct call so that the package's entire use of
// clientcmd is one line a reader can find, and so that a test can prove the
// parse is reached before anything else. It is never reassigned in production.
var clientcmdLoad = clientcmd.Load

// Authority is a validated Kubernetes API authority. **It holds no secret.**
//
// It is what a caller may carry around, record and hand to a report: the
// category of credential, the operator's context choice, and the logical
// endpoint the credential is bound to. A token, a private key, a certificate, a
// credential path, a kubeconfig path and a proxy URL are all absent, and there
// is no field any of them could occupy.
type Authority struct {
	// Mode is one of servicekubernetes.AuthMode*.
	Mode string

	// Context is the selected kubeconfig context, or empty in-cluster.
	Context string

	// Endpoint is the API server, and it is the only thing a Kubernetes
	// credential authorizes.
	Endpoint security.Endpoint
}

// Inspect validates a target and everything its declaration reaches, and
// connects to nothing.
//
// # What it proves
//
// That the target's shape is legal; that the kubeconfig exists, parses and
// declares the named context; that the selected cluster and user carry **no**
// prohibited construct; that exactly one credential is declared between the
// target and that user; and that the API server URL is an https URL with a host.
//
// # Why it is separate from Connect
//
// Because it is the answer to *"is this configuration usable"*, and that
// question has to be answerable before a run starts. The fleet layer calls it
// while decoding a target, so a kubeconfig carrying an `exec` stanza fails the
// whole configuration at exit 2 with nothing dialled — rather than becoming one
// target's execution failure at exit 4, which is the defect Phase 9.1C found in
// the credential path and fixed for the same reason.
//
// credentialSupplied says whether the target declares a credential of its own.
// It is a boolean rather than the credential because Inspect runs where no
// secret has been resolved yet, and because the *number* of declared credentials
// is the only thing the ambiguity check needs.
//
// # In-cluster inspection reads nothing
//
// It cannot: the projected token, the projected CA and KUBERNETES_SERVICE_HOST
// exist only inside the pod, and a configuration must be checkable on a laptop.
// So in-cluster mode's logical endpoint is the API Service's own name, which is
// true everywhere, and the material is resolved at Connect.
func Inspect(target Target, credentialSupplied bool) (Authority, error) {
	if err := target.Validate(); err != nil {
		return Authority{}, err
	}

	if target.InCluster {
		if credentialSupplied {
			return Authority{}, fmt.Errorf("%w: in-cluster mode authenticates as the pod's "+
				"ServiceAccount, so a target credential would be a second identity nobody "+
				"asked for; remove one of the two", ErrTarget)
		}
		endpoint, err := security.NewEndpoint(InClusterHost, InClusterPort)
		if err != nil {
			return Authority{}, fmt.Errorf("%w: %w", ErrTarget, err)
		}
		return Authority{Mode: servicekubernetes.AuthModeInCluster, Endpoint: endpoint}, nil
	}

	view, err := loadKubeconfig(target.Kubeconfig, target.Context, credentialSupplied)
	if err != nil {
		return Authority{}, err
	}
	endpoint, err := view.endpoint()
	if err != nil {
		return Authority{}, err
	}
	return Authority{Mode: view.mode, Context: target.Context, Endpoint: endpoint}, nil
}

// endpoint is the API server's logical endpoint, for credential binding.
//
// The nil check is unreachable on every path a caller can take today —
// loadKubeconfig returns an error rather than a view with no server — and it is
// here because "unreachable" is a property of the current callers rather than of
// this function. Phase 12.1B's mutation harness found it the direct way: a plant
// that suppressed loadKubeconfig's error reached this line with a zero view, and
// the result was a nil dereference rather than a refusal. A guard turns that into
// an error whatever a future caller does.
func (v kubeconfigView) endpoint() (security.Endpoint, error) {
	if v.server == nil {
		return security.Endpoint{}, fmt.Errorf(
			"%w: no API server was resolved for this target", ErrTarget)
	}
	port, err := serverPort(v.server)
	if err != nil {
		return security.Endpoint{}, err
	}
	endpoint, err := security.NewEndpoint(v.server.Hostname(), port)
	if err != nil {
		return security.Endpoint{}, fmt.Errorf("%w: %w", ErrTarget, err)
	}
	return endpoint, nil
}

// inClusterSource is where in-cluster material is read from.
//
// A struct rather than four constants so a test can supply its own without a
// pod, a kubelet or a projected volume. Production uses defaultInClusterSource
// and nothing else assigns it.
type inClusterSource struct {
	host      string
	port      string
	tokenPath string
	caPath    string

	// serverName is the identity TLS verifies, and in production it is always
	// InClusterHost.
	//
	// It is a field rather than a constant for one reason: a hermetic test serves
	// a certificate for its own loopback address, and a fixed override would make
	// every in-cluster test a certificate test. Production never sets it to
	// anything else, and TestTheInClusterSourceVerifiesTheAPIServiceName pins
	// that.
	serverName string
}

// The standard projected ServiceAccount locations, which are part of the
// Kubernetes API contract rather than a convention.
const (
	inClusterTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // a path, not a credential
	inClusterCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// defaultInClusterSource reads the two variables the kubelet injects.
//
// This is the only environment read in the Kubernetes path, and it is here — in
// the adapter, at execution — rather than in the configuration layer. A
// configuration must mean the same thing on the machine it is written on and the
// pod it runs in, so nothing about a target is decided by an ambient variable
// (ADR 0071 section 8.3); what an ambient variable may decide is where the
// already-declared in-cluster identity actually lives.
func defaultInClusterSource() inClusterSource {
	return inClusterSource{
		host:       os.Getenv("KUBERNETES_SERVICE_HOST"),
		port:       os.Getenv("KUBERNETES_SERVICE_PORT"),
		tokenPath:  inClusterTokenPath,
		caPath:     inClusterCAPath,
		serverName: InClusterHost,
	}
}

// resolve turns the in-cluster source into the same view a kubeconfig produces.
//
// **svcdoctor reads the projected token itself**, exactly as it reads a
// kubeconfig tokenFile, and rest.Config.BearerTokenFile is never set. That
// declines client-go's token-refreshing transport deliberately: a refresh is a
// reread on a schedule svcdoctor does not control, inside a process that runs
// once and exits. One diagnosis needs one token.
func (s inClusterSource) resolve() (kubeconfigView, error) {
	if s.host == "" || s.port == "" {
		return kubeconfigView{}, fmt.Errorf("%w: in-cluster mode was selected and "+
			"KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT is not set, so this process "+
			"is not running in a Kubernetes pod", ErrTarget)
	}
	server, err := url.Parse("https://" + joinHostPort(s.host, s.port))
	if err != nil || server.Hostname() == "" {
		return kubeconfigView{}, fmt.Errorf("%w: KUBERNETES_SERVICE_HOST and "+
			"KUBERNETES_SERVICE_PORT do not form a usable API server address", ErrTarget)
	}

	token, err := readBoundedFile(s.tokenPath, maxPEMBytes, "projected ServiceAccount token")
	if err != nil {
		return kubeconfigView{}, err
	}
	caData, err := readBoundedFile(s.caPath, maxPEMBytes, "projected ServiceAccount CA")
	if err != nil {
		return kubeconfigView{}, err
	}

	view := kubeconfigView{
		server: server,
		caData: caData,
		// The identity verified is the API Service's name, not the cluster IP the
		// connection is made to. The serving certificate covers both, and naming
		// the one the credential is bound to is the stronger of the two checks.
		serverName: s.serverName,
		mode:       servicekubernetes.AuthModeInCluster,
		token:      trimTokenBytes(token),
	}
	if view.token == "" {
		return kubeconfigView{}, fmt.Errorf(
			"%w: the projected ServiceAccount token is empty", ErrTarget)
	}
	return view, nil
}

// joinHostPort brackets an IPv6 literal.
//
// Written out rather than imported so this package does not pull `net` in for
// one formatting rule, which is the same reason security.Endpoint.String does
// it by hand. A host containing a colon is an IPv6 literal; a DNS name never
// contains one.
func joinHostPort(host, port string) string {
	if len(host) > 0 && host[0] != '[' && containsColon(host) {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// Connection is a live, authorized pair of typed Kubernetes clients.
//
// Two typed group clients and nothing else. The full kubernetes.Clientset is
// refused because it is a capability surface: it puts every group and verb one
// method call away, and every guardrail in this package would become review
// discipline instead of a compile error.
type Connection struct {
	core      corev1client.CoreV1Interface
	discovery discoveryv1client.DiscoveryV1Interface
	authority Authority
}

// Authority returns the validated authority this connection was built under.
func (c *Connection) Authority() Authority { return c.authority }

// Connect validates the target again, resolves the credential and builds the
// clients. **It performs no network operation.**
//
// Re-validating is deliberate. Inspect ran at configuration time, possibly
// minutes earlier and possibly in a different process; a kubeconfig that gained
// an `exec` stanza in between must not be reachable because an earlier pass said
// it was clean. The refusal is cheap and the alternative is a
// time-of-check/time-of-use hole in the one check that matters most.
func Connect(target Target, credential security.Credential) (*Connection, error) {
	return connectFrom(target, credential, defaultInClusterSource())
}

func connectFrom(
	target Target, credential security.Credential, source inClusterSource,
) (*Connection, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}

	supplied := !credential.IsZero()
	var (
		view Authority
		raw  kubeconfigView
		err  error
	)
	if target.InCluster {
		if supplied {
			return nil, fmt.Errorf("%w: in-cluster mode authenticates as the pod's "+
				"ServiceAccount, so a target credential would be a second identity nobody "+
				"asked for; remove one of the two", ErrTarget)
		}
		if raw, err = source.resolve(); err != nil {
			return nil, err
		}
		endpoint, endpointErr := security.NewEndpoint(InClusterHost, InClusterPort)
		if endpointErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrTarget, endpointErr)
		}
		view = Authority{Mode: raw.mode, Endpoint: endpoint}
	} else {
		if raw, err = loadKubeconfig(target.Kubeconfig, target.Context, supplied); err != nil {
			return nil, err
		}
		endpoint, endpointErr := raw.endpoint()
		if endpointErr != nil {
			return nil, endpointErr
		}
		view = Authority{Mode: raw.mode, Context: target.Context, Endpoint: endpoint}
	}

	bound, err := bindCredential(raw, credential, view.Endpoint)
	if err != nil {
		return nil, err
	}

	config, err := buildRESTConfig(raw, view.Endpoint, bound)
	if err != nil {
		return nil, err
	}

	core, err := corev1client.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("%w: the Kubernetes core client could not be built", ErrTarget)
	}
	discovery, err := discoveryv1client.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: the Kubernetes discovery.k8s.io client could not be built", ErrTarget)
	}
	return &Connection{core: core, discovery: discovery, authority: view}, nil
}

// bindCredential produces the one credential this connection may use.
//
// # Every mode ends here, and every mode ends bound to the API server
//
// A credential the target supplied is checked rather than trusted: its own
// binding must already be this endpoint. **The composition root may not rebind a
// credential** (ADR 0050 section 4), so a mismatch is a refusal and never a
// silent re-binding.
//
// Material read out of a kubeconfig or a projected volume is wrapped here, and
// wrapped *bound* — so a Pod IP, a ClusterIP or an EndpointSlice address cannot
// obtain it either. That is what makes "Kubernetes credentials never reach a
// discovered endpoint" a property of the type rather than a rule: there is no
// accessor that returns the secret without naming an endpoint, and only one
// endpoint matches.
func bindCredential(
	raw kubeconfigView, supplied security.Credential, endpoint security.Endpoint,
) (security.Credential, error) {
	if !supplied.IsZero() {
		if !supplied.Endpoint().Equal(endpoint) {
			return security.Credential{}, fmt.Errorf(
				"%w: the credential is bound to %s and this target's API server is %s",
				ErrTarget, supplied.Endpoint(), endpoint)
		}
		return supplied, nil
	}

	var material string
	switch raw.mode {
	case servicekubernetes.AuthModeToken, servicekubernetes.AuthModeTokenFile,
		servicekubernetes.AuthModeInCluster:
		material = raw.token
	case servicekubernetes.AuthModeClientCert:
		material = string(raw.keyPEM)
	default:
		return security.Credential{}, fmt.Errorf(
			"%w: no authentication mode was selected", ErrTarget)
	}
	if material == "" {
		return security.Credential{}, fmt.Errorf(
			"%w: the selected credential resolved to nothing", ErrTarget)
	}

	// The identity is empty on purpose. Kubernetes authentication carries no
	// username in any of the four modes: a bearer token and a client certificate
	// both *are* the identity, and the API server decides who they name.
	credential, err := security.NewCredential(endpoint, "", security.NewSecret(material))
	if err != nil {
		return security.Credential{}, fmt.Errorf("%w: %w", ErrTarget, err)
	}
	return credential, nil
}

// buildRESTConfig assembles the connection by hand from validated fields.
//
// # Nothing is handed to clientcmd
//
// clientcmd parsed the document and its job ended there. This builds the
// rest.Config field by field, which is what makes the refusals in kubeconfig.go
// belt-and-braces rather than the only line of defence: **ExecProvider and
// AuthProvider are never assigned on any path**, so a configuration capable of
// running a program cannot be constructed here even by mistake.
//
// # The proxy is set explicitly, and that is a vantage decision
//
// Leaving Proxy nil would make client-go fall back to net/http's environment
// proxy support, so HTTP_PROXY or HTTPS_PROXY in the ambient environment would
// silently change the network position every claim in the report is scoped to —
// a variable the report never saw deciding what the report means (ADR 0092
// section 2.4). A function returning no URL is a direct dial and cannot be
// influenced.
func buildRESTConfig(
	raw kubeconfigView, endpoint security.Endpoint, credential security.Credential,
) (*rest.Config, error) {
	config := &rest.Config{
		Host: raw.server.String(),
		TLSClientConfig: rest.TLSClientConfig{
			CAData:     raw.caData,
			ServerName: raw.serverName,
		},
		Proxy: directDial,
		// Left at zero deliberately: every request carries the run's context, so
		// the deadline is the target's own budget and there is no second,
		// independent one to reason about.
		Timeout: 0,
	}
	if err := applyCredential(config, raw, endpoint, credential); err != nil {
		return nil, err
	}
	return config, nil
}

// directDial is the Proxy function. It selects no proxy, ever.
func directDial(*http.Request) (*url.URL, error) { return nil, nil }

// applyCredential is the **one** place a Kubernetes secret becomes plaintext.
//
// Exactly one production security.Reveal call site exists for Kubernetes, and it
// is the line below. `forbidigo` fails the build on a second one, and this
// package is named in that rule's exclusion list, which is what makes this site
// deliberate rather than incidental (ADR 0094 section 6.2).
//
// The plaintext is written straight into the field that puts it on the wire and
// is never stored anywhere else: not in a struct this package keeps, not in a
// log line, not in an error, and — because AttrValue has no constructor that
// accepts one — not in evidence.
//
// The endpoint is named on the way in, so the binding is checked before the
// value exists. A credential for another endpoint returns an error here and
// produces no bytes at all.
func applyCredential(
	config *rest.Config, raw kubeconfigView,
	endpoint security.Endpoint, credential security.Credential,
) error {
	secret, err := credential.SecretFor(endpoint)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTarget, err)
	}

	plaintext := security.Reveal(secret)
	if plaintext == "" {
		return fmt.Errorf("%w: the selected credential resolved to nothing", ErrTarget)
	}

	switch raw.mode {
	case servicekubernetes.AuthModeClientCert:
		// rest.Config embeds TLSClientConfig, so these are its CertData and
		// KeyData fields. client-go builds the crypto/tls configuration itself,
		// which is why this adapter needs no crypto/tls import — and depguard
		// denies it one, so an adapter cannot interrogate a connection to
		// re-derive what a handshake proved.
		config.CertData = raw.certPEM
		config.KeyData = []byte(plaintext)
	default:
		config.BearerToken = plaintext
	}
	return nil
}
