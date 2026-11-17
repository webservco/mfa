<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * Everything here reveals the secret: show it to the user only, never log or store it.
 */
final readonly class Enrollment implements DataTransferInterface
{
    public function __construct(public string $provisioningUri, public string $manualKey, public string $qrCodeSvg,)
    {
    }
}
