<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Service;

use InvalidArgumentException;
use Override;
use SensitiveParameter;
use UnexpectedValueException;
use WebServCo\Mfa\Contract\SecretEncryptionServiceInterface;

use function base64_decode;
use function base64_encode;
use function random_bytes;
use function sodium_crypto_aead_xchacha20poly1305_ietf_decrypt;
use function sodium_crypto_aead_xchacha20poly1305_ietf_encrypt;
use function strlen;
use function substr;

use const SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
use const SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
use const SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

/**
 * XChaCha20-Poly1305 (libsodium). Stored format: version byte, random nonce, ciphertext with tag, all in base64.
 * The version byte is also part of the associated data, so it can't be changed without failing the decryption.
 */
final readonly class SodiumSecretEncryptionService implements SecretEncryptionServiceInterface
{
    private const string VERSION = "\x01";
    private const int NONCE_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private const int MINIMUM_LENGTH = 1 + self::NONCE_LENGTH + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

    public function __construct(#[SensitiveParameter] private string $key,)
    {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new InvalidArgumentException('The encryption key must be 32 bytes long.');
        }
    }

    #[Override]
    public function decrypt(string $ciphertext, string $associatedData): string
    {
        $decoded = base64_decode($ciphertext, true);

        if ($decoded === false || strlen($decoded) < self::MINIMUM_LENGTH || $decoded[0] !== self::VERSION) {
            throw new UnexpectedValueException('Unknown ciphertext format.');
        }

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($decoded, 1 + self::NONCE_LENGTH),
            self::VERSION . $associatedData,
            substr($decoded, 1, self::NONCE_LENGTH),
            $this->key,
        );

        if ($plaintext === false) {
            throw new UnexpectedValueException('Unable to decrypt: wrong key, wrong data or changed ciphertext.');
        }

        return $plaintext;
    }

    #[Override]
    public function encrypt(#[SensitiveParameter] string $plaintext, string $associatedData,): string
    {
        $nonce = random_bytes(self::NONCE_LENGTH);

        return base64_encode(
            self::VERSION . $nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                self::VERSION . $associatedData,
                $nonce,
                $this->key,
            ),
        );
    }
}
