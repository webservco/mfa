<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract\Storage;

use WebServCo\Mfa\Model\DataTransfer\TotpCredential;

/**
 * TOTP credentials of one realm, one per account. Changes that guard a rule are single conditional statements.
 */
interface TotpCredentialStorageInterface
{
    /**
     * Confirms a pending credential; false when there is no pending credential.
     */
    public function confirm(string $accountId, int $confirmedAt): bool;

    /**
     * Records the time step as used; false when it is not greater than the last used one (replay).
     */
    public function consumeTimeStep(string $accountId, int $timeStep): bool;

    public function delete(string $accountId): bool;

    public function fetch(string $accountId): ?TotpCredential;

    /**
     * Adds one failure and returns the new count; 0 when the account has no credential.
     */
    public function incrementFailedAttempts(string $accountId): int;

    public function lock(string $accountId, int $lockedUntil): bool;

    /**
     * Clears the failure count and the lock.
     */
    public function resetFailedAttempts(string $accountId): bool;

    /**
     * Stores a pending credential, replacing a pending one. A confirmed credential is never replaced.
     */
    public function savePending(string $accountId, string $secretCiphertext, int $createdAt): bool;
}
