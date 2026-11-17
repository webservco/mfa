<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Override;
use SensitiveParameter;
use WebServCo\Mfa\Contract\QrCodeServiceInterface;

final class SvgQrCodeService implements QrCodeServiceInterface
{
    // Pixels. The SVG scales, so this is only the default display size.
    private const int SIZE = 256;

    #[Override]
    public function createSvg(#[SensitiveParameter] string $content,): string
    {
        $writer = new Writer(new ImageRenderer(new RendererStyle(self::SIZE), new SvgImageBackEnd()));

        return $writer->writeString($content);
    }
}
