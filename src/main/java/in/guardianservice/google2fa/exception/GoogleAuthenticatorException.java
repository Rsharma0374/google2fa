package in.guardianservice.google2fa.exception;

/**
 * Base exception for Google Authenticator service
 */
public class GoogleAuthenticatorException extends RuntimeException {
    public GoogleAuthenticatorException(String message) {
        super(message);
    }

    public GoogleAuthenticatorException(String message, Throwable cause) {
        super(message, cause);
    }
}
