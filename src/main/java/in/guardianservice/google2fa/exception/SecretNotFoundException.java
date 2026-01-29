package in.guardianservice.google2fa.exception;

/**
 * Exception thrown when TOTP secret is not found for a user
 */
public class SecretNotFoundException extends GoogleAuthenticatorException{

    public SecretNotFoundException(String message) {
        super(message);
    }
}
