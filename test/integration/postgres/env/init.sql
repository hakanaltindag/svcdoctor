SET password_encryption = 'scram-sha-256';
CREATE ROLE scramuser LOGIN PASSWORD 'sc RAM-pw~7Kv2';
CREATE ROLE trustuser LOGIN;
CREATE ROLE clearuser LOGIN PASSWORD 'cleartext-pw';
SET password_encryption = 'md5';
CREATE ROLE md5user   LOGIN PASSWORD 'md5-pw';
