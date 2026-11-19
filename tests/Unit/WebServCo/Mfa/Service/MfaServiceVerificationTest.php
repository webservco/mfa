<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\MfaFixture;
use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Model\DataTransfer\MfaStatus;
use WebServCo\Mfa\Model\DataTransfer\RecoveryCodeRecord;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;
use WebServCo\Mfa\Model\VerificationResult;
use WebServCo\Mfa\Service\MfaService;
use WebServCo\Mfa\Service\RecoveryCodeService;
use WebServCo\Mfa\Service\Storage\PDORecoveryCodeStorage;
use WebServCo\Mfa\Service\Storage\PDOTotpCredentialStorage;
use WebServCo\Mfa\Service\SvgQrCodeService;
use WebServCo\Mfa\Service\TotpCredentialService;
use WebServCo\Mfa\Service\TotpService;

/**
 * verify(): single use, time window, throttling and locks, recovery codes. The clock is fixed and moved by hand.
 */
#[CoversClass(MfaService::class)]
#[UsesClass(Enrollment::class)]
#[UsesClass(MfaStatus::class)]
#[UsesClass(PDORecoveryCodeStorage::class)]
#[UsesClass(PDOTotpCredentialStorage::class)]
#[UsesClass(RecoveryCodeRecord::class)]
#[UsesClass(RecoveryCodeService::class)]
#[UsesClass(SvgQrCodeService::class)]
#[UsesClass(TotpCredential::class)]
#[UsesClass(TotpCredentialService::class)]
#[UsesClass(TotpService::class)]
final class MfaServiceVerificationTest extends TestCase
{
    private const string ACCOUNT_ID = MfaFixture::ACCOUNT_ID;

    public function testTheConfirmationCodeCanNotBeUsedAgain(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();

        self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, $fixture->getAppCode()));
    }

    public function testAValidCodeIsAcceptedOnce(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();
        $fixture->advanceClock(30);
        $code = $fixture->getAppCode();

        self::assertSame(VerificationResult::Accepted, $this->verifyCode($fixture, $code));
        self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, $code));
    }

    public function testTheCodeOfThePreviousTimeStepIsAccepted(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();
        $fixture->advanceClock(90);

        self::assertSame(VerificationResult::Accepted, $this->verifyCode($fixture, $fixture->getAppCode(-1)));
    }

    public function testFiveFailuresLockForFifteenMinutes(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();
        $wrongCode = $fixture->getWrongCode();

        for ($attempt = 1; $attempt <= 4; $attempt += 1) {
            self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, $wrongCode));
        }

        self::assertSame(VerificationResult::Locked, $this->verifyCode($fixture, $wrongCode));
        $fixture->advanceClock(30);
        self::assertSame(VerificationResult::Locked, $this->verifyCode($fixture, $fixture->getAppCode()));
        self::assertTrue($fixture->getMfaService()->getStatus(self::ACCOUNT_ID)->isLocked);
        $fixture->advanceClock(900);
        self::assertSame(VerificationResult::Accepted, $this->verifyCode($fixture, $fixture->getAppCode()));
        // The success reset the count: one more failure doesn't lock.
        self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, $fixture->getWrongCode()));
    }

    public function testTwentyFailuresLockUntilMfaIsDisabled(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();

        for ($attempt = 1; $attempt <= 20; $attempt += 1) {
            // Wait out each 15-minute lock, so that every attempt is checked and counted.
            $fixture->advanceClock(901);
            $this->verifyCode($fixture, $fixture->getWrongCode());
        }

        $fixture->advanceClock(86_400);

        self::assertSame(VerificationResult::Locked, $this->verifyCode($fixture, $fixture->getAppCode()));
        self::assertTrue($fixture->getMfaService()->getStatus(self::ACCOUNT_ID)->isLocked);

        $fixture->getMfaService()->disable(self::ACCOUNT_ID);

        self::assertFalse($fixture->getMfaService()->getStatus(self::ACCOUNT_ID)->isEnabled);
    }

    public function testARecoveryCodeIsAcceptedOnce(): void
    {
        $fixture = new MfaFixture();
        $recoveryCode = $this->getFirstCode($fixture->enroll());

        self::assertSame(VerificationResult::AcceptedRecoveryCode, $this->verifyCode($fixture, $recoveryCode));
        self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, $recoveryCode));
        self::assertSame(9, $fixture->getMfaService()->getStatus(self::ACCOUNT_ID)->remainingRecoveryCodes);
    }

    public function testWrongRecoveryCodesCountAsFailures(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();

        for ($attempt = 1; $attempt <= 4; $attempt += 1) {
            self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, 'AAAAA-AAAAA'));
        }

        self::assertSame(VerificationResult::Locked, $this->verifyCode($fixture, 'AAAAA-AAAAA'));
    }

    public function testVerifyRejectsAnyCodeWithoutEnabledMfa(): void
    {
        $fixture = new MfaFixture();

        self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, '123456'));

        $fixture->getMfaService()->startEnrollment(self::ACCOUNT_ID, 'user@example.com');

        self::assertSame(VerificationResult::Rejected, $this->verifyCode($fixture, $fixture->getAppCode()));
    }

    /**
     * @param list<string> $codes
     */
    private function getFirstCode(array $codes): string
    {
        foreach ($codes as $code) {
            return $code;
        }

        self::fail('There are no codes.');
    }

    private function verifyCode(MfaFixture $fixture, string $code): VerificationResult
    {
        return $fixture->getMfaService()->verify(self::ACCOUNT_ID, $code);
    }
}
