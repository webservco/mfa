<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WebServCo\Mfa\Service\RecoveryCodeService;

use function array_unique;

#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeServiceTest extends TestCase
{
    public function testGenerateCodesReturnsTenDistinctCodesInDisplayFormat(): void
    {
        $codes = (new RecoveryCodeService())->generateCodes();

        self::assertCount(10, $codes);
        self::assertCount(10, array_unique($codes));

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/', $code);
        }
    }

    #[DataProvider('validInputProvider')]
    public function testNormalizeCodeAcceptsTheWaysPeopleTypeACode(string $input, string $expected): void
    {
        self::assertSame($expected, (new RecoveryCodeService())->normalizeCode($input));
    }

    #[DataProvider('invalidInputProvider')]
    public function testNormalizeCodeRejectsWhatCanNotBeACode(string $input): void
    {
        self::assertNull((new RecoveryCodeService())->normalizeCode($input));
    }

    public function testAHashedCodeVerifiesInAnyTypedForm(): void
    {
        $service = new RecoveryCodeService();
        $hash = $service->hashCode('ABCDE-FGHJK');

        self::assertNotSame('ABCDEFGHJK', $hash);
        self::assertTrue($service->verifyCode('abcde fghjk', $hash));
        self::assertFalse($service->verifyCode('ABCDE-FGHJM', $hash));
        self::assertFalse($service->verifyCode('not a code', $hash));
    }

    public function testHashCodeRejectsAnInvalidCode(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Not a recovery code.');

        (new RecoveryCodeService())->hashCode('ABCDE');
    }

    public function testEveryGeneratedCodeCanBeHashedAndVerified(): void
    {
        $service = new RecoveryCodeService();
        foreach ($service->generateCodes() as $code) {
            self::assertTrue($service->verifyCode($code, $service->hashCode($code)));
        }
    }

    /**
     * @return array<string,array{0:string,1:string}>
     */
    public static function validInputProvider(): array
    {
        return [
            'display format' => ['ABCDE-FGHJK', 'ABCDEFGHJK'],
            'letters read as digits' => ['O0IL1-23456', '0011123456'],
            'lower case' => ['abcde-fghjk', 'ABCDEFGHJK'],
            'spaces' => [' abcde fghjk ', 'ABCDEFGHJK'],
            'without separator' => ['abcdefghjk', 'ABCDEFGHJK'],
        ];
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function invalidInputProvider(): array
    {
        return [
            'empty' => [''],
            'other separator' => ['ABCDE_FGHJK'],
            'too long' => ['ABCDE-FGHJKM'],
            'too short' => ['ABCDE'],
            'U is not used' => ['ABCDE-FGHJU'],
        ];
    }
}
