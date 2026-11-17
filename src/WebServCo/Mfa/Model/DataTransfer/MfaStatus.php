<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

final readonly class MfaStatus implements DataTransferInterface
{
    public function __construct(public bool $isEnabled, public bool $isLocked, public int $remainingRecoveryCodes,)
    {
    }
}
