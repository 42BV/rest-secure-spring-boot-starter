package nl._42.restsecure.autoconfigure.authentication.mfa;

public class MfaException extends RuntimeException {

    public MfaException(String message, Exception cause) {
        super(message, cause);
    }
    
    public MfaException(String message) {
        super(message);
    }
}
