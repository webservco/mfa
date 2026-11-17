<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Factory;

use Override;
use UnexpectedValueException;
use WebServCo\Configuration\Contract\ConfigurationGetterInterface;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceFactoryInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceInterface;
use WebServCo\Mfa\Service\SodiumSecretEncryptionService;
use WebServCo\Mfa\Service\SvgQrCodeService;
use WebServCo\Mfa\Service\TotpCredentialService;
use WebServCo\Mfa\Service\TotpService;

use function base64_decode;

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
        return new TotpCredentialService(
            $credentialStorage,
            new SodiumSecretEncryptionService($this->getEncryptionKey()),
            new SvgQrCodeService(),
            new TotpService(),
            $realm,
            $this->configurationGetter->getString('MFA_ISSUER'),
        );
    }

    private function getEncryptionKey(): string
    {
        $key = base64_decode($this->configurationGetter->getString('MFA_ENCRYPTION_KEY'), true);

        if ($key === false) {
            throw new UnexpectedValueException('MFA_ENCRYPTION_KEY is not valid base64.');
        }

        return $key;
    }
}
