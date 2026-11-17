<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract\Storage;

/**
 * Recovery code hashes of one realm. Plain codes are never stored.
 */
interface RecoveryCodeStorageInterface
{
    /**
     * Marks the code as used; false when it was already used or belongs to another account.
     */
    public function consume(string $accountId, int $id, int $usedAt): bool;

    public function countUnused(string $accountId): int;

    public function deleteAll(string $accountId): bool;

    /**
     * @return list<\WebServCo\Mfa\Model\DataTransfer\RecoveryCodeRecord>
     */
    public function fetchUnused(string $accountId): array;

    /**
     * Replaces all the account's codes, in one transaction.
     *
     * @param list<string> $codeHashes
     */
    public function replace(string $accountId, array $codeHashes, int $createdAt): bool;
}
