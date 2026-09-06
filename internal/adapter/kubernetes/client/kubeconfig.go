package client

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// maxKubeconfigBytes bounds the file svcdoctor is willing to parse.
//
// A kubeconfig is a small document — a handful of clusters, users and contexts —
// and 4 MiB is roughly three orders of magnitude above any real one. It exists
// so that a path pointing at something that is not a kubeconfig is refused by
// size rather than decoded, and so a parse cannot be made to allocate without
// bound.
const maxKubeconfigBytes = 4 << 20

// maxPEMBytes bounds a CA bundle, a client certificate or a private key file.
//
// The same reasoning at a smaller scale. A CA bundle carrying a full public
// trust store is under 300 KiB; 1 MiB is a ceiling nothing legitimate reaches.
const maxPEMBytes = 1 << 20

// kubeconfigView is the validated, narrowed result of reading one kubeconfig.
//
// Every field here was read from the **selected** context's cluster and user and
// from nowhere else. Nothing in it can name a program, a proxy, another
// principal or another cluster, because the constructs that could were refused
// before this value existed.
//
// The secret-bearing fields are deliberately raw here and travel no further:
// resolveCredential turns whichever one the mode selected into a
// security.Secret, and nothing else in this package reads them.
type kubeconfigView struct {
	// server is the API server URL, already checked to be https with a host.
	server *url.URL

	// caData is the cluster's public trust material, or nil for the system pool.
	caData []byte

	// serverName overrides the identity to verify, or is empty.
	serverName string

	// mode is one of servicekubernetes.AuthMode*.
	mode string

	// token is an inline bearer token, or the contents of a tokenFile.
	token string

	// certPEM is the public client certificate. It is not a secret.
	certPEM []byte

	// keyPEM is the client private key. **It is secret material** and is wrapped
	// by resolveCredential before it travels anywhere.
	keyPEM []byte
}

// loadKubeconfig reads, parses and validates one kubeconfig, and refuses every
// construct ADR 0094 section 5.3 froze as prohibited.
//
// # The order is the security contract, not an implementation detail
//
//	read the file
//	    -> clientcmd.Load, which parses and executes nothing
//	    -> resolve the named context, its cluster and its user
//	    -> REFUSE the target if any prohibited construct is present
//	    -> only then read credential material
//
// A refusal issued here cannot be bypassed, because it happens before a
// rest.Config exists and Phase 12.1A measured that client-go invokes an `exec`
// plugin no earlier than the first API request.
//
// # The refusal is scoped to the selected context, and that is safe here
//
// A kubeconfig legitimately holds several contexts, and one cluster's exec-based
// entry is no reason to refuse a run against a different cluster in the same
// file — refusing the whole document would make svcdoctor unusable on the
// machines it is most needed on. What makes the narrow scope safe is that
// buildRESTConfig never hands clientcmd anything: the connection is assembled by
// hand from the fields validated here, so no unselected context, user or cluster
// is reachable at all.
//
// # No refusal message names a construct's contents
//
// The message names **the construct** — "exec", "auth-provider", "proxy-url" —
// and never its command, arguments, environment, executable path or provider
// configuration. Those are attacker-influenceable strings whose only destination
// would be an operator's terminal or a shared report.
func loadKubeconfig(path, contextName string, credentialSupplied bool) (kubeconfigView, error) {
	data, err := readBoundedFile(path, maxKubeconfigBytes, "kubeconfig")
	if err != nil {
		return kubeconfigView{}, err
	}

	// Load parses bytes. It resolves no path, consults no environment variable,
	// merges no second file and — measured in Phase 12.1A — executes nothing.
	parsed, err := clientcmdLoad(data)
	if err != nil {
		// The library's message can quote the document. It is replaced rather
		// than wrapped: a parse error's useful content is *that it did not
		// parse*, and the rest is operator-supplied text on its way to a report.
		return kubeconfigView{}, fmt.Errorf(
			"%w: the kubeconfig at %s is not a valid kubeconfig document",
			ErrTarget, resolvedPath(path))
	}

	context, ok := parsed.Contexts[contextName]
	if !ok || context == nil {
		return kubeconfigView{}, fmt.Errorf(
			"%w: the kubeconfig at %s declares no context named %q",
			ErrTarget, resolvedPath(path), contextName)
	}

	cluster, ok := parsed.Clusters[context.Cluster]
	if !ok || cluster == nil {
		return kubeconfigView{}, fmt.Errorf(
			"%w: context %q names a cluster the kubeconfig does not declare",
			ErrTarget, contextName)
	}

	// A context whose user entry is absent carries no credential of its own. That
	// is legitimate exactly when the target supplied one; otherwise the run would
	// be anonymous, and a diagnostic that silently runs unauthenticated produces a
	// report whose authority nobody can reconstruct.
	authInfo, ok := parsed.AuthInfos[context.AuthInfo]
	if !ok || authInfo == nil {
		if !credentialSupplied {
			return kubeconfigView{}, fmt.Errorf(
				"%w: context %q names no user and the target supplies no credential; "+
					"svcdoctor does not read a Kubernetes API anonymously",
				ErrTarget, contextName)
		}
		authInfo = &clientcmdapi.AuthInfo{}
	}

	if err := refuseProhibitedCluster(cluster); err != nil {
		return kubeconfigView{}, err
	}
	if err := refuseProhibitedAuthInfo(authInfo); err != nil {
		return kubeconfigView{}, err
	}

	server, err := parseServerURL(cluster.Server)
	if err != nil {
		return kubeconfigView{}, err
	}

	view := kubeconfigView{server: server, serverName: cluster.TLSServerName}
	if view.caData, err = readInlineOrFile(
		cluster.CertificateAuthorityData, cluster.CertificateAuthority, "certificate authority",
	); err != nil {
		return kubeconfigView{}, err
	}
	if err := resolveKubeconfigMode(&view, authInfo, credentialSupplied); err != nil {
		return kubeconfigView{}, err
	}
	return view, nil
}

// refuseProhibitedCluster refuses the two cluster-level constructs that would
// silently change what a run measures.
//
// Both were measured in Phase 12.1A to propagate into a usable rest.Config with
// **no error at all**, which is why each is refused explicitly rather than left
// to fail later: silence would have been indistinguishable from absence.
func refuseProhibitedCluster(cluster *clientcmdapi.Cluster) error {
	if cluster.ProxyURL != "" {
		// The URL is never named. A proxy URL may carry credentials in its
		// userinfo, so the one thing this message must not do is repeat it.
		return fmt.Errorf("%w: the selected cluster declares proxy-url, which svcdoctor "+
			"refuses; a proxy changes the network position every claim in the report is "+
			"scoped to, and a report whose vantage differs from the one it states is worse "+
			"than no report", ErrTarget)
	}
	if cluster.InsecureSkipTLSVerify {
		return fmt.Errorf("%w: the selected cluster declares insecure-skip-tls-verify, which "+
			"svcdoctor refuses; it must not silently disable the peer verification it exists "+
			"to perform, and it will not recommend doing so", ErrTarget)
	}
	return nil
}

// refuseProhibitedAuthInfo refuses every prohibited authentication construct.
//
// The list is exhaustive over the fields clientcmdapi.AuthInfo can carry.
// Anything not refused here and not consumed by resolveKubeconfigMode is inert
// by construction, because buildRESTConfig copies fields rather than handing the
// parsed structure to a library that would interpret them.
func refuseProhibitedAuthInfo(authInfo *clientcmdapi.AuthInfo) error {
	// **The exec refusal, and it comes first.** ADR 0072 section 13 refuses
	// arbitrary code execution driven by a configuration file with the reopen
	// condition "None. This is a decision, not a deferral.", and a kubeconfig
	// `exec:` stanza is that shape exactly. No flag enables it; none is created,
	// named or reserved.
	//
	// The practical cost is stated rather than hidden: EKS, GKE and AKS generate
	// exec-based kubeconfigs by default, so those clusters are reachable in first
	// scope only through in-cluster identity or an externally materialized token.
	if authInfo.Exec != nil {
		return fmt.Errorf("%w: the selected user declares an exec credential plugin, which "+
			"svcdoctor refuses permanently; a configuration file must not be able to make "+
			"svcdoctor run a local program, and no flag enables it. Use in-cluster identity, "+
			"a tokenFile, or a token supplied through the target's own credential reference",
			ErrTarget)
	}
	// auth-provider fails closed twice. This is the first: it is refused here.
	// The second is that no plugin/pkg/client/auth package is imported anywhere
	// in svcdoctor, so no provider is registered and none could be constructed
	// even if this check were removed. Belt and braces, deliberately.
	if authInfo.AuthProvider != nil {
		return fmt.Errorf("%w: the selected user declares an auth-provider, which svcdoctor "+
			"refuses; the cloud providers historically shipped as auth-providers execute "+
			"local commands, and none is registered in this build", ErrTarget)
	}
	if authInfo.Impersonate != "" || authInfo.ImpersonateUID != "" ||
		len(authInfo.ImpersonateGroups) > 0 || len(authInfo.ImpersonateUserExtra) > 0 {
		// The impersonated principal is not named. It is an identity from a file
		// on its way to a shareable report, and the construct is what the
		// operator has to remove.
		return fmt.Errorf("%w: the selected user declares impersonation, which svcdoctor "+
			"refuses; a diagnostic that silently acts as another principal produces a report "+
			"whose authority cannot be reconstructed, and impersonation needs an RBAC grant "+
			"svcdoctor's minimum Role deliberately does not request", ErrTarget)
	}
	if authInfo.Username != "" || authInfo.Password != "" {
		return fmt.Errorf("%w: the selected user declares basic authentication, which "+
			"svcdoctor refuses; it is deprecated in Kubernetes and is not one of the four "+
			"supported modes", ErrTarget)
	}
	return nil
}

// resolveKubeconfigMode selects exactly one authentication mode, and refuses a
// user that declares more than one or none.
//
// # Ambiguity is refused rather than resolved by precedence
//
// A precedence rule would mean a kubeconfig carrying both a token and a client
// certificate authenticates as whichever svcdoctor happens to prefer, and an
// operator reading the file could not tell which. That is the same reasoning
// config.NewTargetID applies to a duplicated identifier: a repeat is refused
// rather than resolved by position.
func resolveKubeconfigMode(
	view *kubeconfigView, authInfo *clientcmdapi.AuthInfo, credentialSupplied bool,
) error {
	hasToken := authInfo.Token != ""
	hasTokenFile := authInfo.TokenFile != ""
	hasCert := len(authInfo.ClientCertificateData) > 0 || authInfo.ClientCertificate != ""
	hasKey := len(authInfo.ClientKeyData) > 0 || authInfo.ClientKey != ""

	declared := 0
	for _, present := range []bool{credentialSupplied, hasToken, hasTokenFile, hasCert || hasKey} {
		if present {
			declared++
		}
	}
	if declared > 1 {
		return fmt.Errorf("%w: the target and the selected kubeconfig user between them declare "+
			"more than one credential; svcdoctor refuses the ambiguity rather than choosing "+
			"one, because a configuration that authenticates as whichever credential a tool "+
			"happens to prefer is one nobody can audit", ErrTarget)
	}

	switch {
	case credentialSupplied:
		// The bearer token the target's own credential reference names. The value
		// is resolved by the fleet resolver or by the leaf command, under the
		// existing secret discipline, and arrives here already bound to this
		// endpoint — so nothing about it is read from the kubeconfig at all.
		view.mode = servicekubernetes.AuthModeToken
		return nil

	case hasToken:
		view.mode = servicekubernetes.AuthModeToken
		view.token = authInfo.Token
		return nil

	case hasTokenFile:
		// **svcdoctor reads the file, never client-go.**
		// rest.Config.BearerTokenFile is deliberately never set: it would let the
		// library read a secret svcdoctor never masked, never bounded and never
		// bound to an endpoint, and would reread it on a schedule svcdoctor does
		// not control. Resolved once, here, then held as a security.Secret.
		token, err := readBoundedFile(authInfo.TokenFile, maxPEMBytes, "token file")
		if err != nil {
			return err
		}
		view.mode = servicekubernetes.AuthModeTokenFile
		view.token = trimTokenBytes(token)
		if view.token == "" {
			return fmt.Errorf("%w: the token file named by the selected user is empty",
				ErrTarget)
		}
		return nil

	case hasCert || hasKey:
		if !hasCert || !hasKey {
			return fmt.Errorf("%w: the selected user declares a client certificate without a "+
				"key, or a key without a certificate; both are required", ErrTarget)
		}
		certPEM, err := readInlineOrFile(
			authInfo.ClientCertificateData, authInfo.ClientCertificate, "client certificate")
		if err != nil {
			return err
		}
		keyPEM, err := readInlineOrFile(
			authInfo.ClientKeyData, authInfo.ClientKey, "client key")
		if err != nil {
			return err
		}
		view.mode = servicekubernetes.AuthModeClientCert
		view.certPEM = certPEM
		view.keyPEM = keyPEM
		return nil

	default:
		return fmt.Errorf("%w: neither the target nor the selected kubeconfig user declares a "+
			"credential, and svcdoctor does not read a Kubernetes API anonymously", ErrTarget)
	}
}

// parseServerURL validates the API server address.
//
// # A plaintext API server is refused
//
// svcdoctor transmits a credential to whatever this names, and every one of the
// four supported modes ends with either a bearer token in a request header or a
// private key in a handshake. ADR 0028 and ADR 0030 fixed that a password
// crosses only a verified channel, and an `http://` server URL is not one. The
// refusal is a configuration error, so it is stated before anything is sent
// rather than discovered by the operator after it was.
func parseServerURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: the selected cluster declares no server URL", ErrTarget)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the selected cluster's server URL cannot be parsed",
			ErrTarget)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: the selected cluster's server URL uses the %q scheme; "+
			"svcdoctor presents a credential to the API server and will not do so over a "+
			"channel it cannot verify", ErrTarget, parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: the selected cluster's server URL names no host", ErrTarget)
	}
	return parsed, nil
}

// serverPort returns the API server's port, defaulting to 443.
//
// 443 is the scheme's own default rather than a number chosen here, which is why
// the Kubernetes factory can declare it as its DefaultPort without inventing
// anything.
func serverPort(u *url.URL) (uint16, error) {
	if u.Port() == "" {
		return 443, nil
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%w: the selected cluster's server URL names port %q, which is "+
			"not a port", ErrTarget, u.Port())
	}
	return uint16(port), nil
}

// readBoundedFile reads one operator-named file under a size ceiling.
//
// # Only files the target authorizes are ever opened
//
// The kubeconfig path, a token file, a client certificate and key, a CA bundle,
// and in-cluster the standard projected paths. **No path discovered from remote
// API data is ever opened**: a path arriving inside a Kubernetes object is data,
// not an instruction, and nothing in this package passes one here.
//
// # The message names the resolved path
//
// Symlinks are followed, as they are for --password-file, and the resolved path
// is what any message names — so a symlink cannot make svcdoctor claim a file it
// did not read. No filesystem path reaches canonical evidence at all; these
// strings exist only on the configuration-error path, which is stderr.
func readBoundedFile(path string, limit int64, what string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: no %s path was supplied", ErrTarget, what)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: the %s at %s cannot be read", ErrTarget, what,
			resolvedPath(path))
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w: the %s path %s is a directory", ErrTarget, what,
			resolvedPath(path))
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: the %s at %s is %d bytes, above the %d byte maximum",
			ErrTarget, what, resolvedPath(path), info.Size(), limit)
	}

	data, err := os.ReadFile(path) //nolint:gosec // the path is named by the target, and the
	// authorized set is closed: see the doc comment above.
	if err != nil {
		return nil, fmt.Errorf("%w: the %s at %s cannot be read", ErrTarget, what,
			resolvedPath(path))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: the %s at %s is empty", ErrTarget, what, resolvedPath(path))
	}
	if int64(len(data)) > limit {
		// Stat and ReadFile see two different moments. A file that grew between
		// them is refused rather than truncated.
		return nil, fmt.Errorf("%w: the %s at %s grew past the %d byte maximum while it was "+
			"being read", ErrTarget, what, resolvedPath(path), limit)
	}
	return data, nil
}

// readInlineOrFile takes the inline form when present and the file otherwise.
//
// Both are absent for optional material such as a CA bundle, which returns nil
// and means "use the system trust store". A caller that requires the material
// checks for that itself.
func readInlineOrFile(inline []byte, path, what string) ([]byte, error) {
	if len(inline) > 0 {
		if len(inline) > maxPEMBytes {
			return nil, fmt.Errorf("%w: the inline %s is %d bytes, above the %d byte maximum",
				ErrTarget, what, len(inline), maxPEMBytes)
		}
		out := make([]byte, len(inline))
		copy(out, inline)
		return out, nil
	}
	if path == "" {
		return nil, nil
	}
	return readBoundedFile(path, maxPEMBytes, what)
}

// resolvedPath names the file that was actually opened.
//
// EvalSymlinks failing is not itself an error worth reporting — the caller is
// already reporting one — so the written path is used unchanged in that case.
func resolvedPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// trimTokenBytes removes the trailing newline a token file almost always carries.
//
// Only ASCII whitespace at the ends, and nothing else: a bearer token is opaque
// and svcdoctor must not alter its interior. A file written by `kubectl` or by
// the kubelet's projected volume ends in "\n", and sending that byte would make
// every request fail with a header the server rejects.
func trimTokenBytes(data []byte) string {
	start, end := 0, len(data)
	for start < end && isASCIISpace(data[start]) {
		start++
	}
	for end > start && isASCIISpace(data[end-1]) {
		end--
	}
	return string(data[start:end])
}

func isASCIISpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
