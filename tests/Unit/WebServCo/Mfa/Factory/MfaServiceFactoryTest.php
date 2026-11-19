<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Factory;

use InvalidArgumentException;
use OutOfBoundsException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\SqlitePDOContainer;
use Throwable;
use UnexpectedValueException;
use WebServCo\Configuration\Contract\ConfigurationGetterInterface;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;
use WebServCo\Mfa\Factory\MfaServiceFactory;
use WebServCo\Mfa\Factory\TotpCredentialServiceFactory;
use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Service\MfaService;
use WebServCo\Mfa\Service\RecoveryCodeService;
use WebServCo\Mfa\Service\Storage\PDORecoveryCodeStorage;
use WebServCo\Mfa\Service\Storage\PDOTotpCredentialStorage;
use WebServCo\Mfa\Service\SvgQrCodeService;
use WebServCo\Mfa\Service\SystemClock;
use WebServCo\Mfa\Service\TotpCredentialService;
use WebServCo\Mfa\Service\TotpService;

use function array_key_exists;
use function base64_encode;
use function random_bytes;
use function sprintf;

#[CoversClass(MfaServiceFactory::class)]
#[CoversClass(TotpCredentialServiceFactory::class)]
#[UsesClass(Enrollment::class)]
#[UsesClass(MfaService::class)]
#[UsesClass(PDORecoveryCodeStorage::class)]
#[UsesClass(PDOTotpCredentialStorage::class)]
#[UsesClass(RecoveryCodeService::class)]
#[UsesClass(SvgQrCodeService::class)]
#[UsesClass(SystemClock::class)]
#[UsesClass(TotpCredentialService::class)]
#[UsesClass(TotpService::class)]
final class MfaServiceFactoryTest extends TestCase
{
    public function testTheServiceUsesTheConfiguredIssuer(): void
    {
        $mfaService = $this->createFactory(base64_encode(random_bytes(32)))->createMfaService('admin');

        self::assertStringStartsWith(
            'otpauth://totp/Example%20Admin:user%40example.com?',
            $mfaService->startEnrollment('42', 'user@example.com')->provisioningUri,
        );
    }

    public function testAMissingKeyIsReported(): void
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessageIs('Configuration key "MFA_ENCRYPTION_KEY" does not exist.');

        self::assertFalse($this->createFactory(null)->createMfaService('admin')->getStatus('42')->isEnabled);
    }

    public function testAKeyThatIsNotBase64IsRejectedWithoutShowingIt(): void
    {
        $exception = $this->catchException('not base64!');

        self::assertInstanceOf(UnexpectedValueException::class, $exception);
        self::assertSame('MFA_ENCRYPTION_KEY is not valid base64.', $exception->getMessage());
    }

    public function testAKeyOfTheWrongLengthIsRejectedWithoutShowingIt(): void
    {
        $key = base64_encode(random_bytes(16));
        $exception = $this->catchException($key);

        self::assertInstanceOf(InvalidArgumentException::class, $exception);
        self::assertSame('The encryption key must be 32 bytes long.', $exception->getMessage());
        self::assertStringNotContainsString($key, $exception->getMessage());
    }

    private function catchException(string $key): Throwable
    {
        try {
            $this->createFactory($key)->createMfaService('admin');
        } catch (Throwable $throwable) {
            return $throwable;
        }

        self::fail('The factory accepted an invalid key.');
    }

    /**
     * @param ?string $encryptionKey `MFA_ENCRYPTION_KEY`; null: the key is missing.
     */
    private function createFactory(?string $encryptionKey): MfaServiceFactory
    {
        $configuration = ['MFA_ISSUER' => 'Example Admin'];

        if ($encryptionKey !== null) {
            $configuration['MFA_ENCRYPTION_KEY'] = $encryptionKey;
        }

        $configurationGetter = self::createStub(ConfigurationGetterInterface::class);
        $configurationGetter->method('getString')->willReturnCallback(
            static function (string $key) use ($configuration): string {
                if (!array_key_exists($key, $configuration)) {
                    throw new OutOfBoundsException(sprintf('Configuration key "%s" does not exist.', $key));
                }

                return $configuration[$key];
            },
        );

        return new MfaServiceFactory(
            $configurationGetter,
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new SqlitePDOContainer(),
        );
    }
}
