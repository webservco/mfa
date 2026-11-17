<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service;

use InvalidArgumentException;
use Override;
use SensitiveParameter;
use WebServCo\Mfa\Contract\TotpServiceInterface;

use function hash_equals;
use function hash_hmac;
use function http_build_query;
use function implode;
use function intdiv;
use function ord;
use function pack;
use function random_bytes;
use function rawurlencode;
use function sprintf;
use function str_contains;
use function str_pad;
use function str_split;

use const PHP_QUERY_RFC3986;
use const STR_PAD_LEFT;

final class TotpService implements TotpServiceInterface
{
    private const string BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const int DIGITS = 6;
    private const int PERIOD = 30;
    private const int SECRET_BYTES = 20;

    #[Override]
    public function generateSecret(): string
    {
        return random_bytes(self::SECRET_BYTES);
    }

    /**
     * HOTP (RFC 4226 section 5.3) with the time step as the counter.
     */
    #[Override]
    public function getCode(#[SensitiveParameter] string $secret, int $timeStep,): string
    {
        // Counter: 8 bytes, big endian.
        $hash = hash_hmac('sha1', pack('J', $timeStep), $secret, true);
        // Dynamic truncation: the low 4 bits of the last byte give the offset of 4 bytes, read as a 31-bit integer.
        $offset = ord($hash[19]) & 0x0F;
        $value = ((ord($hash[$offset]) & 0x7F) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);

        return str_pad((string) ($value % 10 ** self::DIGITS), self::DIGITS, '0', STR_PAD_LEFT);
    }

    #[Override]
    public function getManualKey(#[SensitiveParameter] string $secret,): string
    {
        return implode(' ', str_split($this->encodeBase32($secret), 4));
    }

    #[Override]
    public function getMatchingTimeStep(
        #[SensitiveParameter]
        string $secret,
        #[SensitiveParameter]
        string $code,
        int $timestamp,
    ): ?int {
        $currentTimeStep = intdiv($timestamp, self::PERIOD);

        foreach ([$currentTimeStep, $currentTimeStep - 1] as $timeStep) {
            if (hash_equals($this->getCode($secret, $timeStep), $code)) {
                return $timeStep;
            }
        }

        return null;
    }

    /**
     * Google Authenticator Key URI format: the issuer is both the label prefix and a parameter.
     */
    #[Override]
    public function getProvisioningUri(#[SensitiveParameter] string $secret, string $issuer, string $label,): string
    {
        foreach ([$issuer, $label] as $part) {
            if ($part === '' || str_contains($part, ':')) {
                throw new InvalidArgumentException('Issuer and label must not be empty or contain a colon.');
            }
        }

        return sprintf(
            'otpauth://totp/%s:%s?%s',
            rawurlencode($issuer),
            rawurlencode($label),
            http_build_query(
                [
                    'algorithm' => 'SHA1',
                    'digits' => self::DIGITS,
                    'issuer' => $issuer,
                    'period' => self::PERIOD,
                    'secret' => $this->encodeBase32($secret),
                ],
                '',
                '&',
                PHP_QUERY_RFC3986,
            ),
        );
    }

    /**
     * RFC 4648 base32 without padding.
     *
     * A lookup table is fine here: the secret is shown to the user in the same response, so a constant-time encoding
     * would protect nothing. The component never decodes base32: the stored secret is the raw bytes.
     */
    private function encodeBase32(#[SensitiveParameter] string $bytes,): string
    {
        $encoded = '';
        $buffer = 0;
        $bitCount = 0;

        foreach (str_split($bytes) as $character) {
            // Only the unread bits matter: at most 4 left over plus the 8 new ones.
            $buffer = (($buffer << 8) | ord($character)) & 0xFFF;
            $bitCount += 8;

            while ($bitCount >= 5) {
                $bitCount -= 5;
                $encoded .= self::BASE32_ALPHABET[($buffer >> $bitCount) & 0x1F];
            }
        }

        if ($bitCount > 0) {
            // The last character takes the remaining bits, padded with zeros on the right.
            $paddingBitCount = 5 - $bitCount;
            $encoded .= self::BASE32_ALPHABET[($buffer << $paddingBitCount) & 0x1F];
        }

        return $encoded;
    }
}
