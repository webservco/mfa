-- webservco/mfa tables for MariaDB and MySQL. Times are Unix seconds.
-- Binary collation: account ids compare exactly, as in the SQLite tests.

CREATE TABLE mfa_totp_credential (
    realm VARCHAR(32) NOT NULL,
    account_id VARCHAR(64) NOT NULL,
    secret_ciphertext VARCHAR(255) NOT NULL,
    confirmed_at INT UNSIGNED NULL,
    last_used_step BIGINT UNSIGNED NULL,
    failed_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until INT UNSIGNED NULL,
    created_at INT UNSIGNED NOT NULL,
    PRIMARY KEY (realm, account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
