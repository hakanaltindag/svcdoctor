-- One role per authentication method, so each row of ADR 0038's mechanism table
-- and each row of ADR 0039's SQLSTATE table has something real to run against.
--
-- Order matters: password_encryption is session state, and a role created while
-- it is 'md5' gets an md5 verifier whatever pg_hba later asks for. The md5 role
-- is created last for that reason.
SET password_encryption = 'scram-sha-256';

-- The supported path. The password spans the printable-ASCII range svcdoctor
-- accepts, space and tilde included.
CREATE ROLE scramuser LOGIN PASSWORD 'sc RAM-pw~7Kv2';

-- No credential is requested for this one.
CREATE ROLE trustuser LOGIN;

-- Observed and declined.
CREATE ROLE clearuser LOGIN PASSWORD 'cleartext-pw';

-- Authenticates, and is then refused CONNECT to closeddb: the 42501 producer.
CREATE ROLE norights LOGIN PASSWORD 'pw-norights';

SET password_encryption = 'md5';
CREATE ROLE md5user LOGIN PASSWORD 'md5-pw';

SET password_encryption = 'scram-sha-256';

-- Refused by pg_hba before authentication is requested. Its password is never
-- evaluated, which is the whole point of the scenario.
CREATE ROLE rejectuser LOGIN PASSWORD 'pw-rejectuser';

-- The redaction canaries. Both names appear nowhere else in the repository, so
-- finding either in a shareable report is unambiguous, and both reach the graph
-- as identity attributes on the startup node.
CREATE ROLE svcdcanaryrole LOGIN PASSWORD 'svcd-canary-pw-9Q7x';

-- Phase 10.3: the 53300 producer, made deterministic by configuration rather
-- than by a race.
--
-- `CONNECTION LIMIT 0` means the server refuses **every** login for this role at
-- InitializeSessionUserId — after authentication has completed and before
-- ReadyForQuery, which is exactly the window ADR 0036 section 5 describes — and
-- reports ERRCODE_TOO_MANY_CONNECTIONS. No connection is held open, no client
-- races another, and nothing has to be cleaned up afterwards, so an interrupted
-- run leaves the fixture exactly as it found it.
--
-- The alternative — lowering `max_connections` and opening sockets until the
-- server runs out — would exhaust a shared server, depend on timing, and leak
-- connections on any path that did not reach its own cleanup.
--
-- It is deliberately a limit on the **role**, and that is a semantic property of
-- the fixture and not only a convenience. `53300` is raised whenever a connection
-- limit applicable to the session being admitted has been reached, and PostgreSQL
-- has several; this role reaches it while the server has connections to spare. So
-- this fixture is the standing counterexample to any claim that `53300` proves the
-- endpoint had no connection slot available, and the integration suite scans the
-- rendered report for exactly those wordings (ADR 0085 section 3.2a).
CREATE ROLE limituser LOGIN PASSWORD 'pw-limituser' CONNECTION LIMIT 0;
