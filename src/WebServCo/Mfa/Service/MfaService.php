<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service;

use InvalidArgumentException;
use OutOfRangeException;
use Override;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use WebServCo\Mfa\Contract\MfaServiceInterface;
use WebServCo\Mfa\Contract\RecoveryCodeServiceInterface;
use WebServCo\Mfa\Contract\Storage\RecoveryCodeStorageInterface;
use WebServCo\Mfa\Contract\Storage\TotpCredentialStorageInterface;
use WebServCo\Mfa\Contract\TotpCredentialServiceInterface;
use WebServCo\Mfa\Model\DataTransfer\Enrollment;
use WebServCo\Mfa\Model\DataTransfer\MfaStatus;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;
use WebServCo\Mfa\Model\VerificationResult;

use function strlen;

/**
 * Each code is accepted once. TOTP and recovery codes share one failure count: from the 5th consecutive failure
 * each failure locks for 15 minutes, and from the 20th the lock stays until disable(). A success resets the count.
 *
 * phpcs: "Signature of method should be placed on a single line" conflicts with "Expected 0 blank lines between
 * attribute and its target, both are on same line": a #[SensitiveParameter] parameter needs a multi-line signature.
 *
 * @phpcs:disable SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature.RequiredSingleLineSignature
 */
final readonly class MfaService implements MfaServiceInterface
{
    private const int LOCK_FAILURES = 5;
    private const int LOCK_SECONDS = 900;
    private const int PERMANENT_LOCK_FAILURES = 20;

    public function __construct(
        private ClockInterface $clock,
        private TotpCredentialServiceInterface $credentialService,
        private TotpCredentialStorageInterface $credentialStorage,
        private RecoveryCodeServiceInterface $recoveryCodeService,
        private RecoveryCodeStorageInterface $recoveryCodeStorage,
    ) {
    }

    #[Override]
    public function confirmEnrollment(
        string $accountId,
        #[SensitiveParameter]
        string $code,
    ): ?array {
        $credential = $this->fetchCredential($accountId);

        if ($credential === null || $credential->confirmedAt !== null) {
            return null;
        }

        $now = $this->getTime();

        if (!$this->credentialService->useCode($accountId, $credential, $code, $now)) {
            return null;
        }

        if (!$this->credentialStorage->confirm($accountId, $now)) {
            return null;
        }

        return $this->replaceRecoveryCodes($accountId, $now);
    }

    #[Override]
    public function disable(string $accountId): bool
    {
        $this->assertAccountId($accountId);
        $this->recoveryCodeStorage->deleteAll($accountId);

        return $this->credentialStorage->delete($accountId);
    }

    #[Override]
    public function getStatus(string $accountId): MfaStatus
    {
        $credential = $this->fetchConfirmedCredential($accountId);

        if ($credential === null) {
            return new MfaStatus(false, false, 0);
        }

        return new MfaStatus(
            true,
            $this->isLocked($credential, $this->getTime()),
            $this->recoveryCodeStorage->countUnused($accountId),
        );
    }

    #[Override]
    public function regenerateRecoveryCodes(string $accountId): array
    {
        if ($this->fetchConfirmedCredential($accountId) === null) {
            throw new OutOfRangeException('MFA is not enabled.');
        }

        return $this->replaceRecoveryCodes($accountId, $this->getTime());
    }

    #[Override]
    public function startEnrollment(string $accountId, string $label): Enrollment
    {
        if ($this->fetchConfirmedCredential($accountId) !== null) {
            throw new OutOfRangeException('MFA is already enabled.');
        }

        return $this->credentialService->createPendingCredential($accountId, $label, $this->getTime());
    }

    #[Override]
    public function verify(
        string $accountId,
        #[SensitiveParameter]
        string $code,
    ): VerificationResult {
        $credential = $this->fetchConfirmedCredential($accountId);

        if ($credential === null) {
            return VerificationResult::Rejected;
        }

        $now = $this->getTime();

        if ($this->isLocked($credential, $now)) {
            return VerificationResult::Locked;
        }

        if ($this->credentialService->useCode($accountId, $credential, $code, $now)) {
            $this->credentialStorage->resetFailedAttempts($accountId);

            return VerificationResult::Accepted;
        }

        if ($this->useRecoveryCode($accountId, $code, $now)) {
            $this->credentialStorage->resetFailedAttempts($accountId);

            return VerificationResult::AcceptedRecoveryCode;
        }

        return $this->recordFailure($accountId, $now);
    }

    private function assertAccountId(string $accountId): bool
    {
        // The column is VARCHAR(64): a longer id could be truncated into another account's id.
        if ($accountId === '' || strlen($accountId) > 64) {
            throw new InvalidArgumentException('The account id must be 1 to 64 characters long.');
        }

        return true;
    }

    private function fetchConfirmedCredential(string $accountId): ?TotpCredential
    {
        $credential = $this->fetchCredential($accountId);

        if ($credential === null || $credential->confirmedAt === null) {
            return null;
        }

        return $credential;
    }

    private function fetchCredential(string $accountId): ?TotpCredential
    {
        $this->assertAccountId($accountId);

        return $this->credentialStorage->fetch($accountId);
    }

    private function getTime(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    private function isLocked(TotpCredential $credential, int $now): bool
    {
        if ($credential->failedAttempts >= self::PERMANENT_LOCK_FAILURES) {
            return true;
        }

        return $credential->lockedUntil !== null && $credential->lockedUntil > $now;
    }

    private function recordFailure(string $accountId, int $now): VerificationResult
    {
        if ($this->credentialStorage->incrementFailedAttempts($accountId) < self::LOCK_FAILURES) {
            return VerificationResult::Rejected;
        }

        $this->credentialStorage->lock($accountId, $now + self::LOCK_SECONDS);

        return VerificationResult::Locked;
    }

    /**
     * @return list<string>
     */
    private function replaceRecoveryCodes(string $accountId, int $now): array
    {
        $codes = $this->recoveryCodeService->generateCodes();
        $codeHashes = [];

        foreach ($codes as $code) {
            $codeHashes[] = $this->recoveryCodeService->hashCode($code);
        }

        $this->recoveryCodeStorage->replace($accountId, $codeHashes, $now);

        return $codes;
    }

    private function useRecoveryCode(
        string $accountId,
        #[SensitiveParameter]
        string $code,
        int $now,
    ): bool {
        if ($this->recoveryCodeService->normalizeCode($code) === null) {
            return false;
        }

        foreach ($this->recoveryCodeStorage->fetchUnused($accountId) as $record) {
            if (!$this->recoveryCodeService->verifyCode($code, $record->codeHash)) {
                continue;
            }

            return $this->recoveryCodeStorage->consume($accountId, $record->id, $now);
        }

        return false;
    }
}
