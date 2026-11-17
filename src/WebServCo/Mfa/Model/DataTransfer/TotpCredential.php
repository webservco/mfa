<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * One account's TOTP credential. Times are Unix seconds; `confirmedAt` is null while the enrollment is pending.
 */
final readonly class TotpCredential implements DataTransferInterface
{
    public function __construct(
        public string $secretCiphertext,
        public ?int $confirmedAt,
        public ?int $lastUsedTimeStep,
        public int $failedAttempts,
        public ?int $lockedUntil,
        public int $createdAt,
    ) {
    }
}
