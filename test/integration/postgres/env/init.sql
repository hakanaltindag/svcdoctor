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
