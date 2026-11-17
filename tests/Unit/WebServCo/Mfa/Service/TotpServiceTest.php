<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WebServCo\Mfa\Service\TotpService;

use function intdiv;
use function strlen;

/**
 * The reference vectors use the RFC test secret, ASCII "12345678901234567890"
 * (base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).
 */
#[CoversClass(TotpService::class)]
final class TotpServiceTest extends TestCase
{
    private const string RFC_SECRET = '12345678901234567890';

    #[DataProvider('rfc4226VectorProvider')]
    public function testGetCodeMatchesTheRfc4226Vectors(int $counter, string $expectedCode): void
    {
        self::assertSame($expectedCode, $this->createService()->getCode(self::RFC_SECRET, $counter));
    }

    #[DataProvider('rfc6238VectorProvider')]
    public function testCodeMatchesTheRfc6238VectorsAtTheirTime(int $timestamp, string $code): void
    {
        self::assertSame(
            intdiv($timestamp, 30),
            $this->createService()->getMatchingTimeStep(self::RFC_SECRET, $code, $timestamp),
        );
    }

    public function testCodeOfThePreviousTimeStepIsAccepted(): void
    {
        // 081804 belongs to time step 37037036 (T 1111111109); T 1111111111 is in step 37037037.
        self::assertSame(
            37_037_036,
            $this->createService()->getMatchingTimeStep(self::RFC_SECRET, '081804', 1_111_111_111),
        );
    }

    public function testCodeFromTwoTimeStepsBackIsRejected(): void
    {
        self::assertNull($this->createService()->getMatchingTimeStep(self::RFC_SECRET, '081804', 1_111_111_141));
    }

    public function testCodeOfTheNextTimeStepIsRejected(): void
    {
        // 050471 belongs to time step 37037037; T 1111111109 is still in step 37037036.
        self::assertNull($this->createService()->getMatchingTimeStep(self::RFC_SECRET, '050471', 1_111_111_109));
    }

    public function testWrongCodeIsRejected(): void
    {
        self::assertNull($this->createService()->getMatchingTimeStep(self::RFC_SECRET, '287083', 59));
    }

    public function testGenerateSecretReturnsTwentyRandomBytes(): void
    {
        $service = $this->createService();
        $secret = $service->generateSecret();

        self::assertSame(20, strlen($secret));
        self::assertNotSame($secret, $service->generateSecret());
    }

    #[DataProvider('rfc4648VectorProvider')]
    public function testGetManualKeyEncodesBase32InGroupsOfFour(string $bytes, string $expectedKey): void
    {
        self::assertSame($expectedKey, $this->createService()->getManualKey($bytes));
    }

    public function testGetManualKeyOfATwentyByteSecretHasEightGroups(): void
    {
        self::assertSame(
            'GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ',
            $this->createService()->getManualKey(self::RFC_SECRET),
        );
    }

    public function testGetProvisioningUriFollowsTheKeyUriFormat(): void
    {
        self::assertSame(
            'otpauth://totp/Example%20Admin:user%40example.com'
            . '?algorithm=SHA1&digits=6&issuer=Example%20Admin&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
            $this->createService()->getProvisioningUri(self::RFC_SECRET, 'Example Admin', 'user@example.com'),
        );
    }

    #[DataProvider('invalidIssuerAndLabelProvider')]
    public function testGetProvisioningUriRejectsAnInvalidIssuerOrLabel(string $issuer, string $label): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Issuer and label must not be empty or contain a colon.');

        $this->createService()->getProvisioningUri(self::RFC_SECRET, $issuer, $label);
    }

    /**
     * RFC 4226 Appendix D: HOTP values for counters 0 to 9.
     *
     * @return array<string,array{0:int,1:string}>
     */
    public static function rfc4226VectorProvider(): array
    {
        return [
            'counter 0' => [0, '755224'],
            'counter 1' => [1, '287082'],
            'counter 2' => [2, '359152'],
            'counter 3' => [3, '969429'],
            'counter 4' => [4, '338314'],
            'counter 5' => [5, '254676'],
            'counter 6' => [6, '287922'],
            'counter 7' => [7, '162583'],
            'counter 8' => [8, '399871'],
            'counter 9' => [9, '520489'],
        ];
    }

    /**
     * RFC 6238 Appendix B, SHA1: the last 6 digits of the 8-digit values.
     *
     * @return array<string,array{0:int,1:string}>
     */
    public static function rfc6238VectorProvider(): array
    {
        return [
            'T 59' => [59, '287082'],
            'T 1111111109' => [1_111_111_109, '081804'],
            'T 1111111111' => [1_111_111_111, '050471'],
            'T 1234567890' => [1_234_567_890, '005924'],
            'T 2000000000' => [2_000_000_000, '279037'],
            'T 20000000000' => [20_000_000_000, '353130'],
        ];
    }

    /**
     * RFC 4648 section 10 base32 vectors, padding removed, grouped by 4.
     *
     * @return array<string,array{0:string,1:string}>
     */
    public static function rfc4648VectorProvider(): array
    {
        return [
            'f' => ['f', 'MY'],
            'fo' => ['fo', 'MZXQ'],
            'foo' => ['foo', 'MZXW 6'],
            'foob' => ['foob', 'MZXW 6YQ'],
            'fooba' => ['fooba', 'MZXW 6YTB'],
            'foobar' => ['foobar', 'MZXW 6YTB OI'],
        ];
    }

    /**
     * @return array<string,array{0:string,1:string}>
     */
    public static function invalidIssuerAndLabelProvider(): array
    {
        return [
            'colon in issuer' => ['Example:Admin', 'user@example.com'],
            'colon in label' => ['Example Admin', 'user:example'],
            'empty issuer' => ['', 'user@example.com'],
            'empty label' => ['Example Admin', ''],
        ];
    }

    private function createService(): TotpService
    {
        return new TotpService();
    }
}
