<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service\Storage;

use InvalidArgumentException;
use Override;
use PDOStatement;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;

use function preg_match;
use function str_replace;

/**
 * Table: `resources/mfa.sql`. The table name replaces `{table}` in the SQL, so it is validated; values are bound.
 */
final readonly class PDOTotpCredentialStorage implements TotpCredentialStorageInterface
{
    public function __construct(
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
        private string $realm,
        private string $tableName = 'mfa_totp_credential',
    ) {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $tableName) !== 1) {
            throw new InvalidArgumentException('Invalid table name.');
        }
    }

    #[Override]
    public function confirm(string $accountId, int $confirmedAt): bool
    {
        return $this->execute(
            'UPDATE {table} SET confirmed_at = ? WHERE realm = ? AND account_id = ? AND confirmed_at IS NULL',
            [$confirmedAt, $this->realm, $accountId],
        )->rowCount() === 1;
    }

    #[Override]
    public function consumeTimeStep(string $accountId, int $timeStep): bool
    {
        return $this->execute(
            'UPDATE {table} SET last_used_step = ?'
            . ' WHERE realm = ? AND account_id = ? AND (last_used_step IS NULL OR last_used_step < ?)',
            [$timeStep, $this->realm, $accountId, $timeStep],
        )->rowCount() === 1;
    }

    #[Override]
    public function delete(string $accountId): bool
    {
        $this->execute('DELETE FROM {table} WHERE realm = ? AND account_id = ?', [$this->realm, $accountId]);

        return true;
    }

    #[Override]
    public function fetch(string $accountId): ?TotpCredential
    {
        $row = $this->pdoContainer->getPDOService()->fetchAssoc(
            $this->execute(
                'SELECT secret_ciphertext, confirmed_at, last_used_step, failed_attempts, locked_until, created_at'
                . ' FROM {table} WHERE realm = ? AND account_id = ?',
                [$this->realm, $accountId],
            ),
        );

        if ($row === []) {
            return null;
        }

        $extraction = $this->dataExtractionContainer->getStrictArrayDataExtractionService();

        return new TotpCredential(
            $extraction->getString($row, 'secret_ciphertext'),
            $extraction->getNullableInt($row, 'confirmed_at'),
            $extraction->getNullableInt($row, 'last_used_step'),
            $extraction->getInt($row, 'failed_attempts'),
            $extraction->getNullableInt($row, 'locked_until'),
            $extraction->getInt($row, 'created_at'),
        );
    }

    #[Override]
    public function incrementFailedAttempts(string $accountId): int
    {
        $this->execute(
            'UPDATE {table} SET failed_attempts = failed_attempts + 1 WHERE realm = ? AND account_id = ?',
            [$this->realm, $accountId],
        );

        $credential = $this->fetch($accountId);

        if ($credential === null) {
            return 0;
        }

        return $credential->failedAttempts;
    }

    #[Override]
    public function lock(string $accountId, int $lockedUntil): bool
    {
        $this->execute(
            'UPDATE {table} SET locked_until = ? WHERE realm = ? AND account_id = ?',
            [$lockedUntil, $this->realm, $accountId],
        );

        return true;
    }

    #[Override]
    public function resetFailedAttempts(string $accountId): bool
    {
        $this->execute(
            'UPDATE {table} SET failed_attempts = 0, locked_until = NULL WHERE realm = ? AND account_id = ?',
            [$this->realm, $accountId],
        );

        return true;
    }

    #[Override]
    public function savePending(string $accountId, string $secretCiphertext, int $createdAt): bool
    {
        $this->execute(
            'DELETE FROM {table} WHERE realm = ? AND account_id = ? AND confirmed_at IS NULL',
            [$this->realm, $accountId],
        );
        // Fails on the primary key when a confirmed credential exists.
        $this->execute(
            'INSERT INTO {table} (realm, account_id, secret_ciphertext, failed_attempts, created_at)'
            . ' VALUES (?, ?, ?, 0, ?)',
            [$this->realm, $accountId, $secretCiphertext, $createdAt],
        );

        return true;
    }

    /**
     * @param list<int|string> $parameters
     */
    private function execute(string $query, array $parameters): PDOStatement
    {
        $statement = $this->pdoContainer->getPDOService()->prepareStatement(
            $this->pdoContainer->getPDO(),
            str_replace('{table}', $this->tableName, $query),
        );
        $statement->execute($parameters);

        return $statement;
    }
}
