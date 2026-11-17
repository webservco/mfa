<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Factory;

use Override;
use WebServCo\Configuration\Contract\ConfigurationGetterInterface;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;
use WebServCo\Mfa\Contract\MfaServiceFactoryInterface;
use WebServCo\Mfa\Contract\MfaServiceInterface;
use WebServCo\Mfa\Service\MfaService;
use WebServCo\Mfa\Service\RecoveryCodeService;
use WebServCo\Mfa\Service\Storage\PDORecoveryCodeStorage;
use WebServCo\Mfa\Service\Storage\PDOTotpCredentialStorage;
use WebServCo\Mfa\Service\SystemClock;

/**
 * The tables are `mfa_totp_credential` and `mfa_recovery_code` (`resources/mfa.sql`). For other table names, build
 * the storages yourself.
 */
final readonly class MfaServiceFactory implements MfaServiceFactoryInterface
{
    public function __construct(
        private ConfigurationGetterInterface $configurationGetter,
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
    ) {
    }

    #[Override]
    public function createMfaService(string $realm): MfaServiceInterface
    {
        $credentialStorage = new PDOTotpCredentialStorage($this->dataExtractionContainer, $this->pdoContainer, $realm);
        $credentialServiceFactory = new TotpCredentialServiceFactory($this->configurationGetter);

        return new MfaService(
            new SystemClock(),
            $credentialServiceFactory->createTotpCredentialService($credentialStorage, $realm),
            $credentialStorage,
            new RecoveryCodeService(),
            new PDORecoveryCodeStorage($this->dataExtractionContainer, $this->pdoContainer, $realm),
        );
    }
}
