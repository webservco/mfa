<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use OutOfRangeException;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;
use WebServCo\Mfa\Service\MfaService;
use WebServCo\Mfa\Service\RecoveryCodeService;
use WebServCo\Mfa\Service\SodiumSecretEncryptionService;
use WebServCo\Mfa\Service\Storage\PDORecoveryCodeStorage;
use WebServCo\Mfa\Service\Storage\PDOTotpCredentialStorage;
use WebServCo\Mfa\Service\SvgQrCodeService;
use WebServCo\Mfa\Service\TotpCredentialService;
use WebServCo\Mfa\Service\TotpService;

use function in_array;
use function intdiv;
use function random_bytes;

/**
 * The MFA services on in-memory SQLite with a fixed clock, and an "authenticator app" that reads the stored secret.
 */
final readonly class MfaFixture
{
    public const string ACCOUNT_ID = '42';

    // In the middle of a 30-second time step.
    public const int START_TIME = 1_800_000_015;

    private FixedClock $clock;
    private TotpCredentialService $credentialService;
    private PDOTotpCredentialStorage $credentialStorage;
    private SodiumSecretEncryptionService $encryptionService;
    private MfaService $mfaService;

    public function __construct()
    {
        $dataExtractionContainer = (new DataExtractionContainerFactory())->createDataExtractionContainer(false);
        $pdoContainer = new SqlitePDOContainer();
        $this->clock = new FixedClock(self::START_TIME);
        $this->credentialStorage = new PDOTotpCredentialStorage($dataExtractionContainer, $pdoContainer, 'admin');
        $this->encryptionService = new SodiumSecretEncryptionService(random_bytes(32));
        $this->credentialService = new TotpCredentialService(
            $this->credentialStorage,
            $this->encryptionService,
            new SvgQrCodeService(),
            new TotpService(),
            'admin',
            'Example Admin',
        );
        $this->mfaService = new MfaService(
            $this->clock,
            $this->credentialService,
            $this->credentialStorage,
            // The lowest bcrypt cost keeps the tests fast; production uses the default.
            new RecoveryCodeService(4),
            new PDORecoveryCodeStorage($dataExtractionContainer, $pdoContainer, 'admin'),
        );
    }

    public function advanceClock(int $seconds): void
    {
        $this->clock->advance($seconds);
    }

    /**
     * Enrolls the account and returns its recovery codes.
     *
     * @return list<string>
     */
    public function enroll(): array
    {
        $this->mfaService->startEnrollment(self::ACCOUNT_ID, 'user@example.com');

        return $this->mfaService->confirmEnrollment(self::ACCOUNT_ID, $this->getAppCode()) ?? [];
    }

    /**
     * The code the app shows now, or a number of time steps away from now.
     */
    public function getAppCode(int $timeStepOffset = 0): string
    {
        return (new TotpService())->getCode(
            $this->encryptionService->decrypt(
                $this->getStoredCredential()->secretCiphertext,
                'admin|' . self::ACCOUNT_ID,
            ),
            intdiv($this->getTime(), 30) + $timeStepOffset,
        );
    }

    public function getCredentialService(): TotpCredentialService
    {
        return $this->credentialService;
    }

    public function getMfaService(): MfaService
    {
        return $this->mfaService;
    }

    public function getStoredCredential(): TotpCredential
    {
        $credential = $this->credentialStorage->fetch(self::ACCOUNT_ID);

        if ($credential === null) {
            throw new OutOfRangeException('The account has no credential.');
        }

        return $credential;
    }

    public function getTime(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    /**
     * A 6-digit code that matches neither the current nor the previous time step.
     */
    public function getWrongCode(): string
    {
        $validCodes = [$this->getAppCode(), $this->getAppCode(-1)];

        foreach (['000000', '111111'] as $code) {
            if (in_array($code, $validCodes, true)) {
                continue;
            }

            return $code;
        }

        return '222222';
    }
}
