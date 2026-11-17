<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;
use WebServCo\Mfa\Service\SodiumSecretEncryptionService;

use function base64_decode;
use function base64_encode;
use function chr;
use function ord;
use function random_bytes;
use function str_repeat;
use function strlen;
use function substr;

#[CoversClass(SodiumSecretEncryptionService::class)]
final class SodiumSecretEncryptionServiceTest extends TestCase
{
    private const string ASSOCIATED_DATA = 'admin|42';
    private const string PLAINTEXT = '12345678901234567890';

    public function testDecryptReturnsThePlaintext(): void
    {
        $service = $this->createService();

        self::assertSame(
            self::PLAINTEXT,
            $service->decrypt($service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA), self::ASSOCIATED_DATA),
        );
    }

    public function testEncryptingTwiceGivesDifferentCiphertexts(): void
    {
        $service = $this->createService();

        self::assertNotSame(
            $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA),
            $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA),
        );
    }

    public function testCiphertextDoesNotContainThePlaintext(): void
    {
        $decoded = $this->decode($this->createService()->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA));

        self::assertStringNotContainsString(self::PLAINTEXT, $decoded);
    }

    public function testChangedCiphertextIsRejected(): void
    {
        $service = $this->createService();
        $decoded = $this->decode($service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA));
        // Flip one bit in the encrypted part.
        $decoded[30] = chr(ord($decoded[30]) ^ 1);

        $this->expectException(UnexpectedValueException::class);

        $service->decrypt(base64_encode($decoded), self::ASSOCIATED_DATA);
    }

    public function testWrongKeyIsRejected(): void
    {
        $ciphertext = $this->createService()->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);

        $this->expectException(UnexpectedValueException::class);

        $this->createService()->decrypt($ciphertext, self::ASSOCIATED_DATA);
    }

    public function testOtherAssociatedDataIsRejected(): void
    {
        $service = $this->createService();
        $ciphertext = $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);

        $this->expectException(UnexpectedValueException::class);

        $service->decrypt($ciphertext, 'admin|43');
    }

    #[DataProvider('unknownFormatProvider')]
    public function testUnknownFormatIsRejected(string $ciphertext): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageIs('Unknown ciphertext format.');

        $this->createService()->decrypt($ciphertext, self::ASSOCIATED_DATA);
    }

    public function testUnknownVersionIsRejected(): void
    {
        $service = $this->createService();
        $decoded = $this->decode($service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA));

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageIs('Unknown ciphertext format.');

        $service->decrypt(base64_encode("\x02" . substr($decoded, 1)), self::ASSOCIATED_DATA);
    }

    public function testKeyOfTheWrongLengthIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The encryption key must be 32 bytes long.');

        $service = new SodiumSecretEncryptionService(random_bytes(31));
        $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);
    }

    public function testCiphertextFitsTheStorageColumn(): void
    {
        $ciphertext = $this->createService()->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);

        self::assertLessThanOrEqual(255, strlen($ciphertext));
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function unknownFormatProvider(): array
    {
        return [
            'empty' => [''],
            'not base64' => ['not base64!'],
            'too short' => [base64_encode("\x01" . str_repeat('a', 39))],
        ];
    }

    private function decode(string $ciphertext): string
    {
        $decoded = base64_decode($ciphertext, true);

        if ($decoded === false) {
            self::fail('The ciphertext is not base64.');
        }

        return $decoded;
    }

    private function createService(): SodiumSecretEncryptionService
    {
        return new SodiumSecretEncryptionService(random_bytes(32));
    }
}
