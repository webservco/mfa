<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Factory;

use Override;
use WebServCo\Configuration\Contract\ConfigurationGetterInterface;
use WebServCo\Encryption\Factory\SecretEncryptionServiceFactory;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceFactoryInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceInterface;
use WebServCo\Mfa\Service\SvgQrCodeService;
use WebServCo\Mfa\Service\TotpCredentialService;
use WebServCo\Mfa\Service\TotpService;

/**
 * Reads `MFA_ENCRYPTION_KEY` (base64 of 32 bytes) and `MFA_ISSUER`. Error messages never contain the key.
 */
final readonly class TotpCredentialServiceFactory implements TotpCredentialServiceFactoryInterface
{
    public function __construct(private ConfigurationGetterInterface $configurationGetter,)
    {
    }

    #[Override]
    public function createTotpCredentialService(
        TotpCredentialStorageInterface $credentialStorage,
        string $realm,
    ): TotpCredentialServiceInterface {
        $encryptionServiceFactory = new SecretEncryptionServiceFactory($this->configurationGetter);

        return new TotpCredentialService(
            $credentialStorage,
            $encryptionServiceFactory->createSecretEncryptionService('MFA_ENCRYPTION_KEY'),
            new SvgQrCodeService(),
            new TotpService(),
            $realm,
            $this->configurationGetter->getString('MFA_ISSUER'),
        );
    }
}
