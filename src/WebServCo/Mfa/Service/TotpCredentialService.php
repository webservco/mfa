<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service;

use InvalidArgumentException;
use Override;
use SensitiveParameter;
use WebServCo\Mfa\Contract\QrCodeServiceInterface;
use WebServCo\Mfa\Contract\SecretEncryptionServiceInterface;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceInterface;
use WebServCo\Mfa\Contract\TotpServiceInterface;
use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;

use function preg_match;
use function str_replace;

/**
 * phpcs: "Signature of method should be placed on a single line" conflicts with "Expected 0 blank lines between
 * attribute and its target, both are on same line": a #[SensitiveParameter] parameter needs a multi-line signature.
 *
 * @phpcs:disable SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature.RequiredSingleLineSignature
 */
final readonly class TotpCredentialService implements TotpCredentialServiceInterface
{
    public function __construct(
        private TotpCredentialStorageInterface $credentialStorage,
        private SecretEncryptionServiceInterface $encryptionService,
        private QrCodeServiceInterface $qrCodeService,
        private TotpServiceInterface $totpService,
        private string $realm,
        private string $issuer,
    ) {
        // The realm is part of the associated data "realm|accountId", so it must not contain "|".
        if (preg_match('/^[A-Za-z0-9_-]{1,32}$/', $realm) !== 1) {
            throw new InvalidArgumentException('The realm must be 1 to 32 letters, digits, "_" or "-".');
        }
    }

    #[Override]
    public function createPendingCredential(string $accountId, string $label, int $now): Enrollment
    {
        $secret = $this->totpService->generateSecret();
        $provisioningUri = $this->totpService->getProvisioningUri($secret, $this->issuer, $label);
        $this->credentialStorage->savePending(
            $accountId,
            $this->encryptionService->encrypt($secret, $this->getAssociatedData($accountId)),
            $now,
        );

        return new Enrollment(
            $provisioningUri,
            $this->totpService->getManualKey($secret),
            $this->qrCodeService->createSvg($provisioningUri),
        );
    }

    #[Override]
    public function useCode(
        string $accountId,
        TotpCredential $credential,
        #[SensitiveParameter]
        string $code,
        int $now,
    ): bool {
        $normalizedCode = str_replace(' ', '', $code);

        if (preg_match('/^\d{6}$/', $normalizedCode) !== 1) {
            return false;
        }

        $timeStep = $this->totpService->getMatchingTimeStep(
            $this->encryptionService->decrypt($credential->secretCiphertext, $this->getAssociatedData($accountId)),
            $normalizedCode,
            $now,
        );

        return $timeStep !== null && $this->credentialStorage->consumeTimeStep($accountId, $timeStep);
    }

    /**
     * Binds the ciphertext to its row: a secret copied to another account or realm doesn't decrypt.
     */
    private function getAssociatedData(string $accountId): string
    {
        return $this->realm . '|' . $accountId;
    }
}
