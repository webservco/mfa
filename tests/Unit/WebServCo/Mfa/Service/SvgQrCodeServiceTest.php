<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use WebServCo\Mfa\Service\SvgQrCodeService;

/**
 * Whether the QR code scans is checked by hand with authenticator apps (see the phase verification).
 */
#[CoversClass(SvgQrCodeService::class)]
final class SvgQrCodeServiceTest extends TestCase
{
    private const string CONTENT = 'otpauth://totp/Example:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function testCreateSvgReturnsAnSvgDocument(): void
    {
        $svg = (new SvgQrCodeService())->createSvg(self::CONTENT);

        self::assertStringStartsWith('<?xml', $svg);
        self::assertStringContainsString('<svg', $svg);
        self::assertStringContainsString('width="256" height="256"', $svg);
    }

    public function testCreateSvgDiffersForDifferentContent(): void
    {
        $service = new SvgQrCodeService();

        self::assertNotSame($service->createSvg(self::CONTENT), $service->createSvg(self::CONTENT . 'X'));
    }
}
