package nl._42.restsecure.autoconfigure.authentication.mfa;

public class MfaException extends Exception {

    public MfaException(String message, Exception cause) {
        super(message, cause);
    }
}
