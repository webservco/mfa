<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;

interface TotpCredentialServiceFactoryInterface
{
    public function createTotpCredentialService(
        TotpCredentialStorageInterface $credentialStorage,
        string $realm,
    ): TotpCredentialServiceInterface;
}
