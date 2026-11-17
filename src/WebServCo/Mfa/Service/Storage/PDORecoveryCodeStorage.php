<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service\Storage;

use InvalidArgumentException;
use Override;
use PDOStatement;
use Throwable;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;
use WebServCo\Mfa\Contract\Storage\RecoveryCodeStorageInterface;
use WebServCo\Mfa\Model\DataTransfer\RecoveryCodeRecord;

use function preg_match;
use function str_replace;

/**
 * Table: `resources/mfa.sql`. The table name replaces `{table}` in the SQL, so it is validated; values are bound.
 */
final readonly class PDORecoveryCodeStorage implements RecoveryCodeStorageInterface
{
    public function __construct(
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
        private string $realm,
        private string $tableName = 'mfa_recovery_code',
    ) {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $tableName) !== 1) {
            throw new InvalidArgumentException('Invalid table name.');
        }
    }

    #[Override]
    public function consume(string $accountId, int $id, int $usedAt): bool
    {
        return $this->execute(
            'UPDATE {table} SET used_at = ? WHERE id = ? AND realm = ? AND account_id = ? AND used_at IS NULL',
            [$usedAt, $id, $this->realm, $accountId],
        )->rowCount() === 1;
    }

    #[Override]
    public function countUnused(string $accountId): int
    {
        $row = $this->pdoContainer->getPDOService()->fetchAssoc(
            $this->execute(
                'SELECT COUNT(*) AS unused FROM {table} WHERE realm = ? AND account_id = ? AND used_at IS NULL',
                [$this->realm, $accountId],
            ),
        );

        return $this->dataExtractionContainer->getStrictArrayDataExtractionService()->getInt($row, 'unused');
    }

    #[Override]
    public function deleteAll(string $accountId): bool
    {
        $this->execute('DELETE FROM {table} WHERE realm = ? AND account_id = ?', [$this->realm, $accountId]);

        return true;
    }

    #[Override]
    public function fetchUnused(string $accountId): array
    {
        $statement = $this->execute(
            'SELECT id, code_hash FROM {table} WHERE realm = ? AND account_id = ? AND used_at IS NULL ORDER BY id',
            [$this->realm, $accountId],
        );
        $pdoService = $this->pdoContainer->getPDOService();
        $extraction = $this->dataExtractionContainer->getStrictArrayDataExtractionService();
        $records = [];
        $row = $pdoService->fetchAssoc($statement);

        while ($row !== []) {
            $records[] = new RecoveryCodeRecord(
                $extraction->getInt($row, 'id'),
                $extraction->getString($row, 'code_hash'),
            );
            $row = $pdoService->fetchAssoc($statement);
        }

        return $records;
    }

    #[Override]
    public function replace(string $accountId, array $codeHashes, int $createdAt): bool
    {
        $pdo = $this->pdoContainer->getPDO();
        $pdo->beginTransaction();

        try {
            $this->execute('DELETE FROM {table} WHERE realm = ? AND account_id = ?', [$this->realm, $accountId]);

            foreach ($codeHashes as $codeHash) {
                $this->execute(
                    'INSERT INTO {table} (realm, account_id, code_hash, created_at) VALUES (?, ?, ?, ?)',
                    [$this->realm, $accountId, $codeHash, $createdAt],
                );
            }
        } catch (Throwable $throwable) {
            $pdo->rollBack();

            throw $throwable;
        }

        return $pdo->commit();
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
