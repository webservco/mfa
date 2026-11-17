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
use WebServCo\Mfa\Model\DataTransfer\RecoveryCodeRecord;
use WebServCo\Mfa\Service\Storage\PDORecoveryCodeStorage;

#[CoversClass(PDORecoveryCodeStorage::class)]
#[UsesClass(RecoveryCodeRecord::class)]
final class PDORecoveryCodeStorageTest extends TestCase
{
    private const string ACCOUNT_ID = '42';

    public function testReplaceStoresTheHashes(): void
    {
        $storage = $this->createStorage();
        $storage->replace(self::ACCOUNT_ID, ['hash-1', 'hash-2'], 1000);

        self::assertSame(['hash-1', 'hash-2'], $this->fetchUnusedHashes($storage));
        self::assertSame(2, $storage->countUnused(self::ACCOUNT_ID));
    }

    public function testReplaceRemovesThePreviousCodes(): void
    {
        $storage = $this->createStorage();
        $storage->replace(self::ACCOUNT_ID, ['old-1', 'old-2'], 1000);
        $storage->replace(self::ACCOUNT_ID, ['new-1'], 2000);

        self::assertSame(['new-1'], $this->fetchUnusedHashes($storage));
    }

    public function testACodeIsConsumedOnlyOnce(): void
    {
        $storage = $this->createStorage();
        $storage->replace(self::ACCOUNT_ID, ['hash-1', 'hash-2'], 1000);
        $codeId = $this->fetchFirstCodeId($storage);

        self::assertTrue($storage->consume(self::ACCOUNT_ID, $codeId, 1100));
        self::assertFalse($storage->consume(self::ACCOUNT_ID, $codeId, 1200));
        self::assertSame(['hash-2'], $this->fetchUnusedHashes($storage));
        self::assertSame(1, $storage->countUnused(self::ACCOUNT_ID));
    }

    public function testAnotherAccountCanNotConsumeTheCode(): void
    {
        $storage = $this->createStorage();
        $storage->replace(self::ACCOUNT_ID, ['hash-1'], 1000);
        $codeId = $this->fetchFirstCodeId($storage);

        self::assertFalse($storage->consume('43', $codeId, 1100));
        self::assertSame(1, $storage->countUnused(self::ACCOUNT_ID));
    }

    public function testDeleteAllRemovesTheCodes(): void
    {
        $storage = $this->createStorage();
        $storage->replace(self::ACCOUNT_ID, ['hash-1'], 1000);
        $storage->deleteAll(self::ACCOUNT_ID);

        self::assertSame(0, $storage->countUnused(self::ACCOUNT_ID));
    }

    public function testRealmsAreIsolated(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $adminStorage = $this->createStorage('admin', $pdoContainer);
        $customerStorage = $this->createStorage('customer', $pdoContainer);
        $adminStorage->replace(self::ACCOUNT_ID, ['admin'], 1000);
        $customerStorage->replace(self::ACCOUNT_ID, ['customer'], 1000);
        $customerStorage->deleteAll(self::ACCOUNT_ID);

        self::assertSame(['admin'], $this->fetchUnusedHashes($adminStorage));
        self::assertSame(0, $customerStorage->countUnused(self::ACCOUNT_ID));
    }

    public function testAFailedReplaceIsRolledBack(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $storage = new PDORecoveryCodeStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
            'admin',
            'missing_table',
        );

        try {
            $storage->replace(self::ACCOUNT_ID, ['hash-1'], 1000);
            self::fail('The replace should fail on a missing table.');
        } catch (PDOException) {
            self::assertFalse($pdoContainer->getPDO()->inTransaction());
        }
    }

    public function testInvalidTableNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Invalid table name.');

        $storage = new PDORecoveryCodeStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new SqlitePDOContainer(),
            'admin',
            'mfa recovery',
        );
        $storage->countUnused(self::ACCOUNT_ID);
    }

    private function createStorage(
        string $realm = 'admin',
        SqlitePDOContainer $pdoContainer = new SqlitePDOContainer(),
    ): PDORecoveryCodeStorage {
        return new PDORecoveryCodeStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
            $realm,
        );
    }

    /**
     * @return list<string>
     */
    private function fetchUnusedHashes(PDORecoveryCodeStorage $storage): array
    {
        $hashes = [];

        foreach ($storage->fetchUnused(self::ACCOUNT_ID) as $record) {
            $hashes[] = $record->codeHash;
        }

        return $hashes;
    }

    private function fetchFirstCodeId(PDORecoveryCodeStorage $storage): int
    {
        foreach ($storage->fetchUnused(self::ACCOUNT_ID) as $record) {
            return $record->id;
        }

        self::fail('There is no unused code.');
    }
}
