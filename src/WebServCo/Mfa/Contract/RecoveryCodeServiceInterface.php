<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

/**
 * Recovery codes: 10 characters of Crockford base32 (about 50 bits), shown as `XXXXX-XXXXX`.
 */
interface RecoveryCodeServiceInterface
{
    /**
     * 10 distinct codes in display format.
     *
     * @return list<string>
     */
    public function generateCodes(): array;

    /**
     * `password_hash` of the normalized code. Throws when the code isn't a valid recovery code.
     */
    public function hashCode(string $code): string;

    /**
     * Upper case, without spaces and dashes, O read as 0 and I or L as 1; null when it can't be a recovery code.
     */
    public function normalizeCode(string $code): ?string;

    public function verifyCode(string $code, string $hash): bool;
}
