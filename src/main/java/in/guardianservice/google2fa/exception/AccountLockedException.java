package in.guardianservice.google2fa.exception;

import java.time.LocalDateTime;

/**
 * Exception thrown when account is locked due to failed attempts
 */
public class AccountLockedException extends GoogleAuthenticatorException {

    private final LocalDateTime lockedUntil;

    public AccountLockedException(String message, LocalDateTime lockedUntil) {
        super(message);
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }
}
