<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Model\DataTransfer\MfaStatus;
use WebServCo\Mfa\Model\VerificationResult;

/**
 * TOTP MFA for the accounts of one realm. Who may call what (for example who may reset MFA) is the application's job.
 */
interface MfaServiceInterface
{
    /**
     * Confirms the pending enrollment with a code from the app. MFA is then enabled, and the recovery codes are
     * returned to be shown once. Null when the code is wrong or nothing is pending.
     *
     * @return list<string>|null
     */
    public function confirmEnrollment(string $accountId, string $code): ?array;

    /**
     * Removes the credential and the recovery codes: the user turns MFA off, or an administrator resets it.
     */
    public function disable(string $accountId): bool;

    public function getStatus(string $accountId): MfaStatus;

    /**
     * Replaces the recovery codes and returns the new ones. Ask the user for a current code first.
     *
     * @return list<string>
     */
    public function regenerateRecoveryCodes(string $accountId): array;

    /**
     * New secret, pending until confirmEnrollment(); replaces a pending one. Throws while MFA is enabled.
     */
    public function startEnrollment(string $accountId, string $label): Enrollment;

    /**
     * Checks a 6-digit TOTP code or a recovery code, each usable once, with throttling.
     */
    public function verify(string $accountId, string $code): VerificationResult;
}
