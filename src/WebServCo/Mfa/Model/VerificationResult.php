<?php

declare(strict_types=1);

namespace WebServCo\Mfa\Model;

enum VerificationResult
{
    case Accepted;

    case AcceptedRecoveryCode;

    // Too many failures: even a valid code is refused until the lock ends (or, after 20 failures, until a reset).
    case Locked;

    case Rejected;
}
