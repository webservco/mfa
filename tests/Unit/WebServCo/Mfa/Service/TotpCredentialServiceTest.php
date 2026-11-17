<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\MfaFixture;
use UnexpectedValueException;
use WebServCo\Mfa\Contract\QrCodeServiceInterface;
use WebServCo\Mfa\Contract\SecretEncryptionServiceInterface;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Contract\TotpServiceInterface;
use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;
use WebServCo\Mfa\Service\MfaService;
use WebServCo\Mfa\Service\RecoveryCodeService;
use WebServCo\Mfa\Service\SodiumSecretEncryptionService;
use WebServCo\Mfa\Service\Storage\PDORecoveryCodeStorage;
use WebServCo\Mfa\Service\Storage\PDOTotpCredentialStorage;
use WebServCo\Mfa\Service\SvgQrCodeService;
use WebServCo\Mfa\Service\TotpCredentialService;
use WebServCo\Mfa\Service\TotpService;

use function str_replace;
use function substr;

#[CoversClass(TotpCredentialService::class)]
#[UsesClass(Enrollment::class)]
#[UsesClass(MfaService::class)]
#[UsesClass(PDORecoveryCodeStorage::class)]
#[UsesClass(PDOTotpCredentialStorage::class)]
#[UsesClass(RecoveryCodeService::class)]
#[UsesClass(SodiumSecretEncryptionService::class)]
#[UsesClass(SvgQrCodeService::class)]
#[UsesClass(TotpCredential::class)]
#[UsesClass(TotpService::class)]
final class TotpCredentialServiceTest extends TestCase
{
    private const string ACCOUNT_ID = MfaFixture::ACCOUNT_ID;

    public function testCreatePendingCredentialStoresTheSecretEncrypted(): void
    {
        $fixture = new MfaFixture();
        $secret = str_replace(' ', '', $this->createPendingCredential($fixture)->manualKey);
        $credential = $fixture->getStoredCredential();

        self::assertNull($credential->confirmedAt);
        self::assertSame(MfaFixture::START_TIME, $credential->createdAt);
        self::assertStringNotContainsString($secret, $credential->secretCiphertext);
    }

    public function testThePendingCredentialMatchesWhatTheUserSees(): void
    {
        $fixture = new MfaFixture();
        $enrollment = $this->createPendingCredential($fixture);

        self::assertStringContainsString(str_replace(' ', '', $enrollment->manualKey), $enrollment->provisioningUri);
        self::assertTrue($this->useCode($fixture, $fixture->getAppCode()));
    }

    public function testUseCodeAcceptsTheCurrentCodeOnce(): void
    {
        $fixture = new MfaFixture();
        $this->createPendingCredential($fixture);
        $code = $fixture->getAppCode();

        self::assertTrue($this->useCode($fixture, $code));
        self::assertFalse($this->useCode($fixture, $code));
    }

    public function testUseCodeAcceptsACodeTypedWithASpace(): void
    {
        $fixture = new MfaFixture();
        $this->createPendingCredential($fixture);
        $code = $fixture->getAppCode();

        self::assertTrue($this->useCode($fixture, substr($code, 0, 3) . ' ' . substr($code, 3)));
    }

    #[DataProvider('malformedCodeProvider')]
    public function testUseCodeRejectsAMalformedCode(string $code): void
    {
        $fixture = new MfaFixture();
        $this->createPendingCredential($fixture);

        self::assertFalse($this->useCode($fixture, $code));
    }

    public function testASecretCopiedToAnotherAccountDoesNotDecrypt(): void
    {
        $fixture = new MfaFixture();
        $this->createPendingCredential($fixture);

        $this->expectException(UnexpectedValueException::class);

        $fixture->getCredentialService()->useCode(
            '43',
            $fixture->getStoredCredential(),
            $fixture->getAppCode(),
            $fixture->getTime(),
        );
    }

    public function testARealmWithASeparatorIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The realm must be 1 to 32 letters, digits, "_" or "-".');

        $service = new TotpCredentialService(
            self::createStub(TotpCredentialStorageInterface::class),
            self::createStub(SecretEncryptionServiceInterface::class),
            self::createStub(QrCodeServiceInterface::class),
            self::createStub(TotpServiceInterface::class),
            'admin|customer',
            'Example Admin',
        );
        self::assertSame('', $service->createPendingCredential(self::ACCOUNT_ID, 'user', 0)->manualKey);
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function malformedCodeProvider(): array
    {
        return [
            'empty' => [''],
            'five digits' => ['12345'],
            'letters' => ['abcdef'],
            'seven digits' => ['1234567'],
        ];
    }

    private function createPendingCredential(MfaFixture $fixture): Enrollment
    {
        return $fixture->getCredentialService()->createPendingCredential(
            self::ACCOUNT_ID,
            'user@example.com',
            $fixture->getTime(),
        );
    }

    private function useCode(MfaFixture $fixture, string $code): bool
    {
        return $fixture->getCredentialService()->useCode(
            self::ACCOUNT_ID,
            $fixture->getStoredCredential(),
            $code,
            $fixture->getTime(),
        );
    }
}
