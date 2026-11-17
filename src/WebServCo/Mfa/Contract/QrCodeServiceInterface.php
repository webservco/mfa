<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

interface QrCodeServiceInterface
{
    /**
     * SVG markup of a QR code holding the content, generated on the server (no external service sees it).
     */
    public function createSvg(string $content): string;
}
