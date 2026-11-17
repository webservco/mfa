<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use DateTimeImmutable;
use Override;
use Psr\Clock\ClockInterface;

final class FixedClock implements ClockInterface
{
    public function __construct(private int $timestamp,)
    {
    }

    public function advance(int $seconds): void
    {
        $this->timestamp += $seconds;
    }

    #[Override]
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . $this->timestamp);
    }
}
