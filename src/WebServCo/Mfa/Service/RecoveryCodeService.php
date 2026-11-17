<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service;

use InvalidArgumentException;
use Override;
use SensitiveParameter;
use WebServCo\Mfa\Contract\RecoveryCodeServiceInterface;

use function count;
use function in_array;
use function password_hash;
use function password_verify;
use function preg_match;
use function random_int;
use function str_replace;
use function strtoupper;
use function strtr;
use function substr;

use const PASSWORD_BCRYPT;

final readonly class RecoveryCodeService implements RecoveryCodeServiceInterface
{
    // Crockford base32: digits and letters without I, L, O and U.
    private const string ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    private const int CODE_COUNT = 10;

    /**
     * @param int $hashCost bcrypt cost; each step doubles the time (about 160 ms per hash at 10 in the DDEV container).
     */
    public function __construct(private int $hashCost = 10,)
    {
    }

    #[Override]
    public function generateCodes(): array
    {
        $codes = [];

        while (count($codes) < self::CODE_COUNT) {
            $code = $this->generateCode();

            if (in_array($code, $codes, true)) {
                continue;
            }

            $codes[] = $code;
        }

        return $codes;
    }

    #[Override]
    public function hashCode(#[SensitiveParameter] string $code,): string
    {
        $normalizedCode = $this->normalizeCode($code);

        if ($normalizedCode === null) {
            throw new InvalidArgumentException('Not a recovery code.');
        }

        return password_hash($normalizedCode, PASSWORD_BCRYPT, ['cost' => $this->hashCost]);
    }

    #[Override]
    public function normalizeCode(#[SensitiveParameter] string $code,): ?string
    {
        $normalizedCode = strtr(strtoupper(str_replace([' ', '-'], '', $code)), 'OIL', '011');

        if (preg_match('/^[0-9A-HJKMNP-TV-Z]{10}$/', $normalizedCode) !== 1) {
            return null;
        }

        return $normalizedCode;
    }

    #[Override]
    public function verifyCode(#[SensitiveParameter] string $code, string $hash,): bool
    {
        $normalizedCode = $this->normalizeCode($code);

        if ($normalizedCode === null) {
            return false;
        }

        return password_verify($normalizedCode, $hash);
    }

    private function generateCode(): string
    {
        $code = '';

        for ($index = 0; $index < 10; $index += 1) {
            $code .= self::ALPHABET[random_int(0, 31)];
        }

        return substr($code, 0, 5) . '-' . substr($code, 5);
    }
}
