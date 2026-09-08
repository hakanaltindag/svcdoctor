package cli

import (
	"fmt"
	"io"
)

// The usage text is written by hand rather than produced by flag.FlagSet.
//
// Two reasons, and both are about the contract rather than about taste. It has
// to be byte-deterministic, because these tests are golden and a Go release that
// reflowed flag's default output would fail them for no product reason. And the
// destination differs by *why* it is being printed — requested help is an
// artifact and goes to stdout, help shown because an invocation was wrong is a
// diagnostic and goes to stderr — which a FlagSet's single Output cannot express.
//
// Nothing here documents a flag that does not exist. Phase 5.2 added
// --password-file, --password-stdin and --shareable, so those appear; a literal
// --password, an environment variable and an interactive prompt do not, because
// ADR 0049 refuses the first and defers the other two. Neither do --color,
// --verbose or inspect.
//
// Nothing here claims a capability either. The Kafka help says what Kafka BASIC
// measures and then says, in as many words, what it does not: no topic,
// partition, consumer-group, lag or throughput inspection, and no cluster,
// broker or partition health. GSSAPI, OAUTHBEARER, AWS_MSK_IAM, mTLS
// authentication and SCRAM-SHA-512 are absent because svcdoctor cannot perform
// them, and a help text that listed them would be advertising a deferred
// capability.
//
// The credential wording says what each flag reads and stops there. Calling a
// source "safe" or "secure" would be an absolute claim about the operator's
// filesystem and pipeline, which this tool is in no position to make.

func (a *App) usageRoot(w io.Writer) {
	_, _ = fmt.Fprint(w, `svcdoctor diagnoses service connectivity from where you run it.

Usage:
  svcdoctor <command> [arguments]

Commands:
  diagnose    measure one service and report what was observed
  run         measure every target in a configuration file

Flags:
  --help      show this help
  --version   show the svcdoctor version

Run "svcdoctor diagnose --help" for the services that can be diagnosed.
`)
}

func (a *App) usageDiagnose(w io.Writer) {
	_, _ = fmt.Fprint(w, `Measure a service and report what was observed.

Usage:
  svcdoctor diagnose <service> [flags]

Services:
  kafka       diagnose a Kafka bootstrap endpoint
  postgres    diagnose a PostgreSQL endpoint
  redis       diagnose a Redis or Valkey endpoint
  rabbitmq    diagnose a RabbitMQ or other AMQP 0-9-1 endpoint
  kubernetes  diagnose one Kubernetes Service's backend publication

Run "svcdoctor diagnose <service> --help" for its flags.
`)
}

func (a *App) usageKafka(w io.Writer) {
	_, _ = fmt.Fprint(w, `Diagnose a Kafka bootstrap endpoint.

svcdoctor behaves as the Kafka client you describe and reports what it observed
at every stage: name resolution, the connection, the TLS handshake, the API
version exchange, SASL mechanism negotiation, authentication and the Metadata
exchange. It then measures DNS, TCP and TLS for every broker endpoint the
cluster advertised.

Usage:
  svcdoctor diagnose kafka --host <host> --sasl-mechanism <name> [flags]

Required:
  --host string             the bootstrap endpoint to diagnose: a hostname or
                            an IPv4 or IPv6 address literal. An address is
                            connected to directly and nothing is resolved, so
                            the report records no name resolution for one.
                            Give IPv6 unbracketed and separately from the
                            port: --host ::1 --port 9092
  --sasl-mechanism string   the SASL mechanism to propose, in uppercase.
                            svcdoctor can perform PLAIN and SCRAM-SHA-256; any
                            other registered name is proposed to the broker and
                            reported as unsupported by svcdoctor, which sends no
                            credential. There is no default: svcdoctor never
                            chooses which framing carries your password, and it
                            never falls back to another mechanism

Connection:
  --port uint               the port to connect to (default 9092)

Execution budget:
  --timeout duration        bound on the whole run (default 30s)
  --step-timeout duration   bound on each individual exchange (default 10s)

Transport encryption:
  --tls string              "require" or "disable" (default "require").
                            "disable" performs no handshake, so the three flags
                            below describe nothing and are refused rather than
                            ignored
  --tls-ca-file path        PEM trust source; empty uses the system store.
                            A supplied file replaces the system roots, it does
                            not add to them, so only its issuers are accepted
  --tls-server-name string  identity to verify and send in SNI; empty uses
                            the host. It is not applied to advertised brokers,
                            which are verified against their own names.
                            --host decides where svcdoctor connects and this
                            decides whose identity it expects there, so
                            --host 10.20.30.40 --tls-server-name kafka.internal
                            connects to the address and verifies the name.
                            With a bare address and no override, the
                            certificate is checked against its IP SANs and no
                            SNI is sent, because SNI carries names only
  --tls-insecure            do not verify the endpoint's identity. Explicit,
                            never automatic, and recorded in the report and on
                            every affected row of the terminal output. A
                            handshake performed this way proves the channel is
                            encrypted and proves nothing about who answered:
                            no chain was validated and no name or address was
                            matched. The channel is unverified, which the
                            credential transport policy refuses, so a
                            credential would be withheld rather than sent

Credential:
  --user string             the principal to authenticate as
  --password-file path      read the credential from a file
  --password-stdin          read the credential from stdin

  At most one password source may be given, and --user is required with one.
  Supplying none is a valid run: an endpoint that demands authentication is
  reported as such, and nothing is sent. A credential authorizes only the
  bootstrap endpoint you named; it is never presented to a broker the cluster
  advertises.

Output:
  --output string           "text" or "json" (default "text")
  --shareable               produce the shareable redacted report instead of
                            the local one, using the same diagnosis

Exit codes:
  0   a report was produced and no error-level problem was proven
  1   a report was produced and an error-level problem was proven
  2   svcdoctor was invoked with something it cannot act on
  3   svcdoctor failed and produced no usable report
  4   a report was produced but svcdoctor's own execution did not finish

Exit code 0 does not mean Kafka metadata was obtained. Read the report.

This is Kafka BASIC. It reports the client journey to one bootstrap endpoint and
the transport reachability of the endpoints that cluster advertised. It reports
nothing about topics, partitions, consumer groups, lag or throughput, and makes
no claim about cluster, broker or partition health.
`)
}

func (a *App) usagePostgres(w io.Writer) {
	_, _ = fmt.Fprint(w, `Diagnose a PostgreSQL endpoint.

svcdoctor behaves as the PostgreSQL client you describe and reports what it
observed at every stage: name resolution, the connection, the in-band SSL
negotiation, the TLS handshake, the startup exchange, authentication and session
establishment.

Usage:
  svcdoctor diagnose postgres --host <host> --user <role> [flags]

Required:
  --host string             the endpoint to diagnose: a hostname or an IPv4 or
                            IPv6 address literal. An address is connected to
                            directly and nothing is resolved, so the report
                            records no name resolution for one. Give IPv6
                            unbracketed and separately from the port:
                            --host ::1 --port 5432
  --user string             the role to connect as

Connection:
  --port uint               the port to connect to (default 5432)
  --database string         the database to select; empty lets the server
                            default it to the role name

Execution budget:
  --timeout duration        bound on the whole run (default 30s)
  --step-timeout duration   bound on each individual exchange (default 10s)

Transport encryption:
  --tls string              "require" or "disable" (default "require").
                            "disable" performs no handshake, so the three flags
                            below describe nothing and are refused rather than
                            ignored
  --tls-ca-file path        PEM trust source; empty uses the system store.
                            A supplied file replaces the system roots, it does
                            not add to them, so only its issuers are accepted
  --tls-server-name string  identity to verify and send in SNI; empty uses
                            the host. --host decides where svcdoctor connects
                            and this decides whose identity it expects there,
                            so --host 10.20.30.40 --tls-server-name db.internal
                            connects to the address and verifies the name.
                            With a bare address and no override, the
                            certificate is checked against its IP SANs and no
                            SNI is sent, because SNI carries names only
  --tls-insecure            do not verify the endpoint's identity. Explicit,
                            never automatic, and recorded in the report and on
                            every affected row of the terminal output. A
                            handshake performed this way proves the channel is
                            encrypted and proves nothing about who answered:
                            no chain was validated and no name or address was
                            matched. The channel is unverified, which the
                            credential transport policy refuses, so a
                            credential would be withheld rather than sent

Credential:
  --password-file path      read the PostgreSQL credential from a file
  --password-stdin          read the PostgreSQL credential from stdin

  At most one may be given. Supplying neither is a valid run: an endpoint that
  demands authentication is reported as such, and nothing is sent.

Output:
  --output string           "text" or "json" (default "text")
  --shareable               produce the shareable redacted report instead of
                            the local one, using the same diagnosis

Exit codes:
  0   a report was produced and no error-level problem was proven
  1   a report was produced and an error-level problem was proven
  2   svcdoctor was invoked with something it cannot act on
  3   svcdoctor failed and produced no usable report
  4   a report was produced but svcdoctor's own execution did not finish

Exit code 0 does not mean a session was established. Read the report.
`)
}

func (a *App) usageRedis(w io.Writer) {
	_, _ = fmt.Fprint(w, `Diagnose a Redis or Valkey endpoint.

svcdoctor behaves as the client you describe and reports what it observed at
every stage: name resolution, the connection, the TLS handshake, the RESP
capability exchange, authentication and one usability probe.

One command diagnoses both implementations. Which one answered is read from the
endpoint's own reply and shown in the report; typing "redis" is not a claim that
the endpoint is Redis.

What this measures, and what it does not:
  * It names no key. There is no read, no write and no keyspace access of any
    kind, so no customer data is touched and none can appear in the report.
  * A successful probe means this endpoint answered PING on this connection. It
    does not mean Redis is healthy, that a backend behind a proxy is available,
    that a cluster is healthy, or that your application's own commands would be
    permitted.
  * Cluster mode is observed and reported. Cluster topology is NOT measured: no
    node is discovered, no slot coverage is checked and no advertised address is
    probed.
  * A Sentinel endpoint is detected and the run stops there, before any
    credential is sent. Sentinel itself is not diagnosed.
  * The credential is sent at most once, in one AUTH command, and only over a
    channel whose peer identity was verified. A plaintext connection and a
    connection with --tls-insecure are both refused, and neither a loopback nor
    a private address changes that. The credential is sent at most once.

Usage:
  svcdoctor diagnose redis --host <host> [flags]

Required:
  --host string             the endpoint to diagnose: a hostname or an IPv4 or
                            IPv6 address literal. An address is connected to
                            directly and nothing is resolved, so the report
                            records no name resolution for one. Give IPv6
                            unbracketed and separately from the port:
                            --host ::1 --port 6379

Connection:
  --port uint               the port to connect to (default 6379)

Execution budget:
  --timeout duration        bound on the whole run (default 30s)
  --step-timeout duration   bound on each individual exchange (default 10s)

Transport encryption:
  --tls string              "require" or "disable" (default "require").
                            Redis serves TLS on a separate port rather than
                            negotiating it in band, so "require" performs an
                            ordinary handshake on the port you named and does
                            not look for a TLS port. "disable" performs no
                            handshake, so the three flags below describe
                            nothing and are refused rather than ignored
  --tls-ca-file path        PEM trust source; empty uses the system store.
                            A supplied file replaces the system roots, it does
                            not add to them, so only its issuers are accepted
  --tls-server-name string  identity to verify and send in SNI; empty uses
                            the host
  --tls-insecure            do not verify the endpoint's identity. Explicit,
                            never automatic, and recorded in the report. The
                            channel is then unverified, which the credential
                            transport policy refuses, so a credential would be
                            withheld rather than sent

Credential:
  --username string         the ACL user to authenticate as. Omit it to send
                            the password-only form of AUTH. The two forms are
                            not equivalent: against a server whose default user
                            is configured nopass, the password-only form
                            reports that no password is configured and the
                            username form succeeds with any password. svcdoctor
                            sends the form you asked for and never substitutes
                            "default"
  --password-file path      read the credential from a file
  --password-stdin          read the credential from stdin
                            The two sources are mutually exclusive, and there
                            is no flag that takes a password as a value: an
                            argument is visible to every process on the host.
                            With no credential at all, a run against an endpoint
                            that demands one records that and exits 0

Output:
  --output string           "text" or "json" (default "text")
  --shareable               produce the shareable redacted report instead of
                            the local one, using the same diagnosis

Exit codes:
  0   a report was produced and no error-level problem was proven
  1   a report was produced and an error-level problem was proven
  2   svcdoctor was invoked with something it cannot act on
  3   svcdoctor failed and produced no usable report
  4   a report was produced but svcdoctor's own execution did not finish

Exit code 0 does not mean this endpoint answered PING. Read the report.
`)
}

// usageRabbitMQ is the fourth service's help.
//
// It follows the three before it and says the same three things in the same
// order: what is measured, what is *not* proven, and what happens to the
// credential. The middle one is the longest because RabbitMQ is the service an
// operator is most likely to assume more from — a connection that opens in a
// virtual host looks like working messaging, and it is not.
func (a *App) usageRabbitMQ(w io.Writer) {
	_, _ = io.WriteString(w, `svcdoctor diagnose rabbitmq - diagnose one RabbitMQ endpoint

Measures one AMQP 0-9-1 connection to one endpoint, from this vantage: name
resolution, the TCP connection, the TLS handshake when one is planned, the
protocol header exchange, SASL PLAIN authentication, and opening the requested
virtual host.

What this proves, and what it does not:
  * RabbitMQ BASIC proves only the AMQP 0-9-1 connection journey through
    Connection.Open-Ok for the requested endpoint and virtual host.
  * It does NOT prove queue existence, exchange existence, publishing,
    consuming, configure/write/read permissions, cluster health, quorum queue
    health, node health, management API health, message delivery, or workload
    correctness.
  * It names no queue and no exchange, opens no channel, and calls no HTTP
    management API. No customer topology is read and none can appear in the
    report.
  * Reaching Connection.Open-Ok means this endpoint answered on this connection
    at this moment. Behind a load balancer svcdoctor cannot say which node
    answered: every node in a cluster reports the same cluster name.
  * The credential is sent at most once, in one Connection.Start-Ok frame, and
    only over a channel whose peer identity was verified. A plaintext connection
    and a connection with --tls-insecure are both refused, and neither a loopback
    nor a private address changes that. There is no retry and no reconnect.
  * svcdoctor implements SASL PLAIN only. It never selects ANONYMOUS, never
    synthesizes a username, and never falls back to another mechanism.

Usage:
  svcdoctor diagnose rabbitmq --host <host> [flags]

Required:
  --host string             the endpoint to diagnose: a hostname or an IPv4 or
                            IPv6 address literal. An address is connected to
                            directly and nothing is resolved, so the report
                            records no name resolution for one. Give IPv6
                            unbracketed and separately from the port:
                            --host ::1 --port 5672

Connection:
  --port uint               the port to connect to (default 5672)
  --vhost string            the virtual host to open (default "/"). The value
                            used is always shown in the report, and a refusal
                            says when the default was used

Authentication:
  --username string         the identity to authenticate as. Never synthesized:
                            svcdoctor does not supply "guest" on your behalf
  --password-file string    read the credential from a file
  --password-stdin          read the credential from stdin

  The two are mutually exclusive. There is no --password flag: a credential
  never appears in argv.

Execution budget:
  --timeout duration        bound on the whole run (default 30s)
  --step-timeout duration   bound on each individual exchange (default 10s).
                            Must exceed 3s: RabbitMQ delays several refusals by
                            exactly that long on purpose, and a shorter budget
                            reports the delay as a local timeout instead of the
                            refusal it is

Transport encryption:
  --tls string              "require" or "disable" (default "require")
  --tls-ca-file string      PEM trust source replacing the system roots
  --tls-server-name string  the identity to verify instead of --host
  --tls-insecure            do not verify the endpoint's identity. Explicit,
                            per-run, recorded in the report, and never an
                            automatic fallback. A credential is NOT sent over an
                            unverified channel

Output:
  --output string           "text" or "json" (default "text")
  --shareable               produce the shareable redacted report

Exit codes:
  0  no ERROR or CRITICAL target-side problem was proven
  1  a target-side problem was found
  2  the invocation could not be used
  3  svcdoctor failed internally
  4  the run was incomplete, which qualifies every conclusion

Exit code 0 does not mean the virtual host was opened. Read the report.
`)
}

// usageKubernetes is the fifth service's help, and the first that describes no
// endpoint.
//
// It follows the four before it and says the same three things in the same
// order: what is measured, what is *not* proven, and what happens to the
// credential. The middle section carries more weight here than anywhere else,
// because a Kubernetes answer is the one an operator is most likely to read as
// a reachability claim — "no ready endpoint" looks like "nothing works", and it
// is not. Every sentence says `publishes`.
//
// It also states the two things a reader would otherwise have to discover: that
// a 401 produces no Kubernetes finding and such a run exits 0, and that no
// Kubernetes distribution is graded. Neither is a defect, and both are worse to
// find out from a report than from the help.
func (a *App) usageKubernetes(w io.Writer) {
	_, _ = fmt.Fprint(w, `Diagnose one Kubernetes Service's backend publication.

svcdoctor makes exactly three bounded Kubernetes API requests for one declared
Service: it reads the Service, lists the Pods that Service's own selector
matches, and lists the EndpointSlices Kubernetes associates with it. It reports
what those reads returned and whether each enumeration was complete.

What this measures, and what it does not:
  * It reports what Kubernetes PUBLISHES. It never says "reachable". svcdoctor
    connects to no Pod, no cluster IP and no endpoint address, so it makes no
    claim about whether traffic flows, about any backend's condition, or about
    the components that publish endpoints.
  * A published endpoint that is terminating is not a dead one, and a Service
    with no ready endpoint may still be receiving traffic. Where that applies,
    the report says so rather than leaving you to assume otherwise.
  * A denied read is never reported as emptiness. The set it would have
    produced is unavailable, which is a different fact. Reaching a page or
    object budget makes a set incomplete rather than empty, and svcdoctor will
    not report an incomplete enumeration as "none".
  * It reads no Pod name, label, phase, condition, image, IP or node, no
    annotation, no Secret, no ConfigMap, no event, no log and no metric. None
    of it is collected, so none of it can appear in the report.
  * It performs no cluster-scoped read, diagnoses no Ingress, Gateway,
    NetworkPolicy or service mesh, and reports no cluster, node or workload
    health.
  * The credential authorizes the Kubernetes API server and nothing else. No
    address discovered through it inherits the credential.
  * A 401 produces no Kubernetes finding: it is authentication rather than
    authorization, and the report localizes where observation stopped instead.
    Such a run exits 0.
  * No Kubernetes distribution or version is graded in docs/COMPATIBILITY.md.

Usage:
  svcdoctor diagnose kubernetes --kubeconfig <path> --context <name> \
                                --namespace <ns> --service-name <name> [flags]
  svcdoctor diagnose kubernetes --in-cluster \
                                --namespace <ns> --service-name <name> [flags]

Required:
  --namespace string        the namespace the Service is in. Never defaulted,
                            never taken from the context, never "default"
  --service-name string     the one Service this run is about

API authority, exactly one of:
  --kubeconfig path         exactly one kubeconfig file. KUBECONFIG is not
                            consulted, ~/.kube/config is not a fallback, and a
                            merge list is not supported: one file, so one
                            invocation means the same thing on every machine
  --in-cluster              authenticate as the pod's own projected
                            ServiceAccount. Explicit only and never a fallback:
                            a mounted token must not make svcdoctor acquire an
                            identity nobody asked for

  --context string          the kubeconfig context to read through. Required
                            with --kubeconfig and refused with --in-cluster.
                            The file's current-context is never used: a
                            defaulted context reads a different cluster on a
                            different machine, and reporting "not found" for
                            the wrong cluster is indistinguishable from a real
                            finding. "kubectl config current-context" tells you
                            what to write

Credential:
  --token-file path         read the bearer token from a file
  --token-stdin             read the bearer token from stdin
                            The two sources are mutually exclusive, and there
                            is no flag that takes a token as a value: an
                            argument is visible to every process on the host.
                            Both are refused with --in-cluster, and refused
                            when the selected kubeconfig user already carries a
                            credential, because two identities is an ambiguity
                            svcdoctor will not resolve by preference. A source
                            that holds no token is refused rather than ignored.
                            Omit both to authenticate as the selected
                            kubeconfig user: a token, a tokenFile svcdoctor
                            reads itself, or a client certificate and key

  An exec credential plugin, an auth-provider, impersonation, a proxy-url,
  insecure-skip-tls-verify and basic authentication are refused before any
  network operation, whichever mode you choose. svcdoctor runs no subprocess
  to obtain a credential.

Execution budget:
  --timeout duration        bound on the whole run (default 30s). There is no
                            per-request flag and no budget flag: the request
                            sequence, the page limits and the object ceilings
                            are fixed, because a lowered ceiling would make an
                            enumeration incomplete and silence a finding

Output:
  --output string           "text" or "json" (default "text")
  --shareable               produce the shareable redacted report instead of
                            the local one, using the same diagnosis

Exit codes:
  0   a report was produced and no error-level problem was proven
  1   a report was produced and an error-level problem was proven
  2   svcdoctor was invoked with something it cannot act on
  3   svcdoctor failed and produced no usable report
  4   a report was produced but svcdoctor's own execution did not finish

Exit code 0 does not mean this Service has a working backend. Read the report.
`)
}

func (a *App) usageRun(w io.Writer) {
	_, _ = fmt.Fprint(w, `Measure every target in a configuration file.

Usage:
  svcdoctor run --config <file> [flags]

Flags:
  --config FILE      the configuration to run; required, and a regular file
  --timeout D        bound on the whole run; overrides the file's run.timeout
  --concurrency N    how many targets run at once, 1-16; overrides run.concurrency
  --output text|json which form to write to stdout
  --shareable        produce the shareable redacted report

Every target is described in the configuration. There are deliberately no
target flags: a flag that edited one target would mean the file no longer
describes the run.

Credentials are named by the configuration and never by a flag. A target
references one with "password: {env: NAME}" or "password: {file: PATH}", and a
password is never written into the file itself.

Targets are independent. One target's failure never stops another, and the
report lists them in the order the file declares.

Exit codes:
  0   every target was measured and no error-level problem was proven
  1   every target was measured and at least one error-level problem was proven
  2   the configuration could not be used; no target was dialled
  3   svcdoctor failed and produced no usable aggregate
  4   an aggregate exists but the run did not finish: a target was cancelled,
      never started, could not be executed locally, or ran out of budget

Exit code 0 does not mean every service works. It means nothing error-level was
proven about any of them. Read the report.
`)
}
