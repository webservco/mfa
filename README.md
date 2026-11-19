# webservco/mfa

A PHP component/library. Please see [webservco/sandbox](https://webservco.github.io/sandbox/) for an example project using these types of components.

TOTP multi-factor authentication (Google Authenticator compatible): enrollment with a QR code, verification with replay protection and throttling, recovery codes and encrypted secrets.

- Requires: PHP extension `xmlwriter`, and `sodium` through `webservco/encryption`; the tables in [`resources/mfa.sql`](resources/mfa.sql); the `MFA_ENCRYPTION_KEY` and `MFA_ISSUER` configuration keys
- Related: `webservco/auth` (an application asks for the code while its login is pending); `webservco/database` (the PDO container); `webservco/encryption` (encrypts the secrets)

---

## Installation

```shell
composer require webservco/mfa
```

---

## Usage

One service per realm, that is per kind of account (`admin`, `customer`…). Account ids are strings of 1 to 64 characters.

```php
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;
use WebServCo\Mfa\Factory\MfaServiceFactory;
use WebServCo\Mfa\Model\VerificationResult;

// \WebServCo\Mfa\Contract\MfaServiceFactoryInterface
$mfaServiceFactory = new MfaServiceFactory(
    $configurationGetter, // \WebServCo\Configuration\Contract\ConfigurationGetterInterface
    (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
    $pdoContainer, // \WebServCo\Database\Contract\PDOContainerInterface
);
// \WebServCo\Mfa\Contract\MfaServiceInterface
$mfaService = $mfaServiceFactory->createMfaService('admin');

// Login: the password was right, and MFA is enabled for the account.
$result = $mfaService->verify($accountId, $submittedCode);
if ($result === VerificationResult::Accepted || $result === VerificationResult::AcceptedRecoveryCode) {
    // Complete the login.
}
// VerificationResult::Locked: too many failures, even a valid code is refused for now.
```

### Enrollment

```php
// \WebServCo\Mfa\Model\DataTransfer\Enrollment
$enrollment = $mfaService->startEnrollment($accountId, $username);
// Show $enrollment->qrCodeSvg (SVG markup) and $enrollment->manualKey, then ask for the code the app shows.

$recoveryCodes = $mfaService->confirmEnrollment($accountId, $submittedCode);
if ($recoveryCodes === null) {
    // Wrong code: ask again. MFA stays off until a code is right.
}
// MFA is enabled. Show the 10 recovery codes once; each works one time instead of a code.
```

### Status, new recovery codes, disable

```php
// \WebServCo\Mfa\Model\DataTransfer\MfaStatus: isEnabled, isLocked, remainingRecoveryCodes
$status = $mfaService->getStatus($accountId);
// Replaces the old codes. Ask for a current code first.
$recoveryCodes = $mfaService->regenerateRecoveryCodes($accountId);
// The user turns MFA off, or an administrator resets a lost device.
$mfaService->disable($accountId);
```

---

## Contracts

| Interface | Implementation | Purpose |
| --- | --- | --- |
| `Contract\MfaServiceFactoryInterface` | `Factory\MfaServiceFactory` | Creates `MfaServiceInterface` for a realm. |
| `Contract\MfaServiceInterface` | `Service\MfaService` | Enrollment, verification, status, recovery codes, disable. |
| `Contract\Storage\TotpCredentialStorageInterface` | `Service\Storage\PDOTotpCredentialStorage` | Encrypted secrets, used time steps, failures. |
| `Contract\Storage\RecoveryCodeStorageInterface` | `Service\Storage\PDORecoveryCodeStorage` | Recovery code hashes. |
| `Psr\Clock\ClockInterface` | `Service\SystemClock` | Current time. |

Namespaces are relative to `WebServCo\Mfa\`. For other table names, build the services as [`MfaServiceFactory`](src/WebServCo/Mfa/Factory/MfaServiceFactory.php) does: the storages take the table name as their last argument.

---

## Configuration

```ini
[MFA]

; Base64 of 32 random bytes; one key per application and environment:
; php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
MFA_ENCRYPTION_KEY = ''
; Shown in the authenticator app. No colon.
MFA_ISSUER = 'Example Admin'
```

---

## Notes

- A code, TOTP or recovery, is accepted once. The current and the previous 30-second step are valid.
- From the 5th consecutive failure each failure locks MFA for 15 minutes; from the 20th it stays locked until `disable()`. A success resets the count.
- `Enrollment` and the recovery codes contain secrets: show them to the user only, never log or store them.
- Keep the key out of the database and back it up. Without it every user has to enroll again.
- Server clocks must be NTP-synchronized. TOTP is not phishing-resistant.
- Who may call `disable()` is the application's decision.

---

## Development

```shell
# Start project.
ddev start
# Install dependencies.
ddev c u
# Run all validations.
ddev c c
# Run unit tests, with coverage (needs Xdebug, which DDEV leaves off).
ddev xdebug on && ddev c test:dox; ddev xdebug off
```

---

## License

[MIT](LICENSE.md)
