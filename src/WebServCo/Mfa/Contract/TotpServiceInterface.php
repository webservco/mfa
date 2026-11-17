<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Contract;

/**
 * TOTP (RFC 6238) with the only settings Google Authenticator honours: SHA1, 6 digits, 30-second time steps.
 *
 * Secrets are raw bytes. Base32 is produced only for the provisioning URI and the manual key.
 */
interface TotpServiceInterface
{
    /**
     * New secret: 20 random bytes (160 bits).
     */
    public function generateSecret(): string;

    /**
     * Code of a time step (Unix time divided by 30): 6 digits, leading zeros kept.
     */
    public function getCode(string $secret, int $timeStep): string;

    /**
     * Secret in base32, in groups of 4 characters, for typing into an authenticator app by hand.
     */
    public function getManualKey(string $secret): string;

    /**
     * Time step the code belongs to, checking the current step and the previous one; null when neither matches.
     *
     * Replay protection is the caller's job: accept each time step only once per account.
     */
    public function getMatchingTimeStep(string $secret, string $code, int $timestamp): ?int;

    /**
     * `otpauth://` URI for the QR code. Neither the issuer nor the label may be empty or contain a colon.
     */
    public function getProvisioningUri(string $secret, string $issuer, string $label): string;
}
