<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

interface MfaServiceFactoryInterface
{
    /**
     * One service per realm, a kind of account such as "admin" or "customer": 1 to 32 letters, digits, "_" or "-".
     */
    public function createMfaService(string $realm): MfaServiceInterface;
}
