<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use WebServCo\Mfa\Contract\RecoveryCodeServiceInterface;
use WebServCo\Mfa\Contract\Storage\RecoveryCodeStorageInterface;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceInterface;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;
use WebServCo\Mfa\Service\MfaService;

/**
 * Races that can't be produced with one database connection, simulated with stubs.
 */
#[CoversClass(MfaService::class)]
#[UsesClass(TotpCredential::class)]
final class MfaServiceConcurrencyTest extends TestCase
{
    public function testConfirmEnrollmentReturnsNullWhenAnotherRequestConfirmedFirst(): void
    {
        $clock = self::createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new DateTimeImmutable('@1800000015'));
        $credentialService = self::createStub(TotpCredentialServiceInterface::class);
        // The code is valid...
        $credentialService->method('useCode')->willReturn(true);
        $credentialStorage = self::createStub(TotpCredentialStorageInterface::class);
        $credentialStorage->method('fetch')->willReturn(new TotpCredential('ciphertext', null, null, 0, null, 0));
        // ...but another request confirmed the credential in between.
        $credentialStorage->method('confirm')->willReturn(false);

        $mfaService = new MfaService(
            $clock,
            $credentialService,
            $credentialStorage,
            self::createStub(RecoveryCodeServiceInterface::class),
            self::createStub(RecoveryCodeStorageInterface::class),
        );

        self::assertNull($mfaService->confirmEnrollment('42', '123456'));
    }
}
