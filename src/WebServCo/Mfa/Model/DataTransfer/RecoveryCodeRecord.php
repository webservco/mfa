<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

final readonly class RecoveryCodeRecord implements DataTransferInterface
{
    public function __construct(public int $id, public string $codeHash,)
    {
    }
}
