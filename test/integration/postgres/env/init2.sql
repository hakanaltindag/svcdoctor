CREATE DATABASE closeddb;
REVOKE CONNECT ON DATABASE closeddb FROM PUBLIC;

-- Owned by the canary role so the healthy canary run really reaches
-- ReadyForQuery rather than tripping over CONNECT.
CREATE DATABASE svcdcanarydb OWNER svcdcanaryrole;
