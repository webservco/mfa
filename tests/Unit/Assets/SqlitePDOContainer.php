<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use PDO;
use WebServCo\Database\Contract\PDOContainerInterface;
use WebServCo\Database\Contract\PDOServiceInterface;
use WebServCo\Database\Service\PDOService;

/**
 * In-memory SQLite database with the component tables (`resources/mfa.sql` in SQLite syntax).
 * PDO is set up like webservco/database's PDOFactory: exceptions, associative fetch, no emulated prepares.
 */
final class SqlitePDOContainer implements PDOContainerInterface
{
    private const string SCHEMA = <<<'SQL'
        CREATE TABLE mfa_totp_credential (
            realm TEXT NOT NULL,
            account_id TEXT NOT NULL,
            secret_ciphertext TEXT NOT NULL,
            confirmed_at INTEGER NULL,
            last_used_step INTEGER NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (realm, account_id)
        );
        CREATE TABLE mfa_recovery_code (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            realm TEXT NOT NULL,
            account_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used_at INTEGER NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX realm_account ON mfa_recovery_code (realm, account_id);
        SQL;

    private ?PDO $pdo = null;

    #[Override]
    public function createPDO(): PDO
    {
        $pdo = new PDO(
            'sqlite::memory:',
            null,
            null,
            [
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ],
        );
        $pdo->exec(self::SCHEMA);

        return $pdo;
    }

    #[Override]
    public function getPDO(): PDO
    {
        return $this->pdo ??= $this->createPDO();
    }

    #[Override]
    public function getPDOService(): PDOServiceInterface
    {
        return new PDOService();
    }
}
