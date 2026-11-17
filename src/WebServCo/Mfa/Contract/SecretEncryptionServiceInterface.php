<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

interface SecretEncryptionServiceInterface
{
    /**
     * Throws when the ciphertext was changed, the key or the associated data differ, or the format is unknown.
     */
    public function decrypt(string $ciphertext, string $associatedData): string;

    /**
     * Base64 text, safe to store. Decrypting needs the same associated data (it binds the ciphertext to its row).
     */
    public function encrypt(string $plaintext, string $associatedData): string;
}
