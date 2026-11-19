<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use InvalidArgumentException;
use OutOfRangeException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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

use function str_repeat;

/**
 * Enrollment, status, recovery code regeneration and disable. Code checks are in MfaServiceVerificationTest.
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
final class MfaServiceEnrollmentTest extends TestCase
{
    private const string ACCOUNT_ID = MfaFixture::ACCOUNT_ID;
    private const string LABEL = 'user@example.com';

    public function testStartEnrollmentReturnsWhatTheUserNeedsToAddTheAccount(): void
    {
        $fixture = new MfaFixture();
        $enrollment = $fixture->getMfaService()->startEnrollment(self::ACCOUNT_ID, self::LABEL);

        self::assertStringStartsWith(
            'otpauth://totp/Example%20Admin:user%40example.com?',
            $enrollment->provisioningUri,
        );
        self::assertMatchesRegularExpression('/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/', $enrollment->manualKey);
        self::assertStringContainsString('<svg', $enrollment->qrCodeSvg);
        self::assertFalse($fixture->getMfaService()->getStatus(self::ACCOUNT_ID)->isEnabled);
    }

    public function testConfirmEnrollmentEnablesMfaAndReturnsTenRecoveryCodes(): void
    {
        $fixture = new MfaFixture();

        self::assertCount(10, $fixture->enroll());
        self::assertEquals(new MfaStatus(true, false, 10), $fixture->getMfaService()->getStatus(self::ACCOUNT_ID));
    }

    public function testConfirmEnrollmentRejectsAWrongCode(): void
    {
        $fixture = new MfaFixture();
        $mfaService = $fixture->getMfaService();
        $mfaService->startEnrollment(self::ACCOUNT_ID, self::LABEL);

        self::assertNull($mfaService->confirmEnrollment(self::ACCOUNT_ID, $fixture->getWrongCode()));
        self::assertFalse($mfaService->getStatus(self::ACCOUNT_ID)->isEnabled);
    }

    public function testConfirmEnrollmentWithoutAPendingEnrollmentReturnsNull(): void
    {
        self::assertNull((new MfaFixture())->getMfaService()->confirmEnrollment(self::ACCOUNT_ID, '123456'));
    }

    public function testStartEnrollmentWhileMfaIsEnabledThrows(): void
    {
        $fixture = new MfaFixture();
        $fixture->enroll();

        $this->expectException(OutOfRangeException::class);
        $this->expectExceptionMessageIs('MFA is already enabled.');

        $fixture->getMfaService()->startEnrollment(self::ACCOUNT_ID, self::LABEL);
    }

    public function testANewEnrollmentReplacesThePendingOne(): void
    {
        $fixture = new MfaFixture();
        $mfaService = $fixture->getMfaService();
        $first = $mfaService->startEnrollment(self::ACCOUNT_ID, self::LABEL);
        $second = $mfaService->startEnrollment(self::ACCOUNT_ID, self::LABEL);

        self::assertNotSame($first->manualKey, $second->manualKey);
        self::assertCount(10, $mfaService->confirmEnrollment(self::ACCOUNT_ID, $fixture->getAppCode()) ?? []);
    }

    public function testRegenerateRecoveryCodesReplacesTheOldOnes(): void
    {
        $fixture = new MfaFixture();
        $mfaService = $fixture->getMfaService();
        $oldCode = $this->getFirstCode($fixture->enroll());
        $newCode = $this->getFirstCode($mfaService->regenerateRecoveryCodes(self::ACCOUNT_ID));

        self::assertSame(VerificationResult::Rejected, $mfaService->verify(self::ACCOUNT_ID, $oldCode));
        self::assertSame(VerificationResult::AcceptedRecoveryCode, $mfaService->verify(self::ACCOUNT_ID, $newCode));
    }

    public function testRegenerateRecoveryCodesRequiresEnabledMfa(): void
    {
        $this->expectException(OutOfRangeException::class);
        $this->expectExceptionMessageIs('MFA is not enabled.');

        self::assertSame([], (new MfaFixture())->getMfaService()->regenerateRecoveryCodes(self::ACCOUNT_ID));
    }

    public function testDisableTurnsMfaOffAndAllowsANewEnrollment(): void
    {
        $fixture = new MfaFixture();
        $mfaService = $fixture->getMfaService();
        $fixture->enroll();

        self::assertTrue($mfaService->disable(self::ACCOUNT_ID));
        self::assertEquals(new MfaStatus(false, false, 0), $mfaService->getStatus(self::ACCOUNT_ID));
        self::assertCount(10, $fixture->enroll());
    }

    #[DataProvider('invalidAccountIdProvider')]
    public function testInvalidAccountIdIsRejected(string $accountId): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The account id must be 1 to 64 characters long.');

        self::assertFalse((new MfaFixture())->getMfaService()->getStatus($accountId)->isEnabled);
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function invalidAccountIdProvider(): array
    {
        return [
            'empty' => [''],
            'longer than the column' => [str_repeat('1', 65)],
        ];
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
}
