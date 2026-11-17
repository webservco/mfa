<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Mfa\Service\Storage;

use InvalidArgumentException;
use PDOException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\SqlitePDOContainer;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;
use WebServCo\Mfa\Model\DataTransfer\TotpCredential;
use WebServCo\Mfa\Service\Storage\PDOTotpCredentialStorage;

#[CoversClass(PDOTotpCredentialStorage::class)]
#[UsesClass(TotpCredential::class)]
final class PDOTotpCredentialStorageTest extends TestCase
{
    private const string ACCOUNT_ID = '42';

    public function testFetchReturnsNullWithoutACredential(): void
    {
        self::assertNull($this->createStorage()->fetch(self::ACCOUNT_ID));
    }

    public function testSavePendingStoresAPendingCredential(): void
    {
        $storage = $this->createStorage();
        $storage->savePending(self::ACCOUNT_ID, 'ciphertext', 1000);

        self::assertEquals(
            new TotpCredential('ciphertext', null, null, 0, null, 1000),
            $storage->fetch(self::ACCOUNT_ID),
        );
    }

    public function testSavePendingReplacesAPendingCredential(): void
    {
        $storage = $this->createStorage();
        $storage->savePending(self::ACCOUNT_ID, 'first', 1000);
        $storage->savePending(self::ACCOUNT_ID, 'second', 2000);

        self::assertSame('second', $this->fetchCredential($storage)->secretCiphertext);
    }

    public function testSavePendingNeverReplacesAConfirmedCredential(): void
    {
        $storage = $this->createStorage();
        $storage->savePending(self::ACCOUNT_ID, 'confirmed', 1000);
        $storage->confirm(self::ACCOUNT_ID, 1100);

        $this->expectException(PDOException::class);

        $storage->savePending(self::ACCOUNT_ID, 'other', 2000);
    }

    public function testConfirmWorksOnlyOnAPendingCredential(): void
    {
        $storage = $this->createStorage();

        self::assertFalse($storage->confirm(self::ACCOUNT_ID, 1100));

        $storage->savePending(self::ACCOUNT_ID, 'ciphertext', 1000);

        self::assertTrue($storage->confirm(self::ACCOUNT_ID, 1100));
        self::assertFalse($storage->confirm(self::ACCOUNT_ID, 1200));
        self::assertSame(1100, $this->fetchCredential($storage)->confirmedAt);
    }

    public function testATimeStepIsConsumedOnlyOnceAndInOrder(): void
    {
        $storage = $this->createStorage();
        $storage->savePending(self::ACCOUNT_ID, 'ciphertext', 1000);

        self::assertTrue($storage->consumeTimeStep(self::ACCOUNT_ID, 50));
        self::assertFalse($storage->consumeTimeStep(self::ACCOUNT_ID, 50));
        self::assertFalse($storage->consumeTimeStep(self::ACCOUNT_ID, 49));
        self::assertTrue($storage->consumeTimeStep(self::ACCOUNT_ID, 51));
        self::assertSame(51, $this->fetchCredential($storage)->lastUsedTimeStep);
    }

    public function testFailuresAreCountedLockedAndReset(): void
    {
        $storage = $this->createStorage();
        $storage->savePending(self::ACCOUNT_ID, 'ciphertext', 1000);

        self::assertSame(1, $storage->incrementFailedAttempts(self::ACCOUNT_ID));
        self::assertSame(2, $storage->incrementFailedAttempts(self::ACCOUNT_ID));

        $storage->lock(self::ACCOUNT_ID, 5000);

        self::assertSame(5000, $this->fetchCredential($storage)->lockedUntil);

        $storage->resetFailedAttempts(self::ACCOUNT_ID);
        $credential = $this->fetchCredential($storage);

        self::assertSame(0, $credential->failedAttempts);
        self::assertNull($credential->lockedUntil);
    }

    public function testIncrementFailedAttemptsWithoutACredentialReturnsZero(): void
    {
        self::assertSame(0, $this->createStorage()->incrementFailedAttempts(self::ACCOUNT_ID));
    }

    public function testDeleteRemovesTheCredential(): void
    {
        $storage = $this->createStorage();
        $storage->savePending(self::ACCOUNT_ID, 'ciphertext', 1000);
        $storage->delete(self::ACCOUNT_ID);

        self::assertNull($storage->fetch(self::ACCOUNT_ID));
    }

    public function testRealmsAreIsolated(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $adminStorage = $this->createStorage('admin', $pdoContainer);
        $customerStorage = $this->createStorage('customer', $pdoContainer);
        $adminStorage->savePending(self::ACCOUNT_ID, 'admin', 1000);
        $customerStorage->savePending(self::ACCOUNT_ID, 'customer', 1000);
        $customerStorage->delete(self::ACCOUNT_ID);

        self::assertSame('admin', $this->fetchCredential($adminStorage)->secretCiphertext);
        self::assertNull($customerStorage->fetch(self::ACCOUNT_ID));
    }

    public function testInvalidTableNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Invalid table name.');

        $storage = new PDOTotpCredentialStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new SqlitePDOContainer(),
            'admin',
            'mfa; DROP TABLE users',
        );
        $storage->fetch(self::ACCOUNT_ID);
    }

    private function createStorage(
        string $realm = 'admin',
        SqlitePDOContainer $pdoContainer = new SqlitePDOContainer(),
    ): PDOTotpCredentialStorage {
        return new PDOTotpCredentialStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
            $realm,
        );
    }

    private function fetchCredential(PDOTotpCredentialStorage $storage): TotpCredential
    {
        $credential = $storage->fetch(self::ACCOUNT_ID);

        if ($credential === null) {
            self::fail('The credential is missing.');
        }

        return $credential;
    }
}
