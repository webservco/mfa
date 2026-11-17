<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;

/**
 * The TOTP credential of an account: its encrypted secret and the codes it produces.
 */
interface TotpCredentialServiceInterface
{
    /**
     * Stores a new secret, encrypted, as a pending credential and returns what the user needs to add it to an app.
     */
    public function createPendingCredential(string $accountId, string $label, int $now): Enrollment;

    /**
     * True when the code belongs to the current or the previous time step and that step wasn't used yet.
     * The step is then recorded as used, so the code can't be replayed.
     */
    public function useCode(string $accountId, TotpCredential $credential, string $code, int $now): bool;
}
