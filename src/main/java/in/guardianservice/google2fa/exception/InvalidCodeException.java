package in.guardianservice.google2fa.exception;
/**
 * Exception thrown when TOTP code validation fails
 */
public class InvalidCodeException extends GoogleAuthenticatorException {

    public InvalidCodeException(String message) {
        super(message);
    }
}
