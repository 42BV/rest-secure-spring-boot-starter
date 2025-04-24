package nl._42.restsecure.autoconfigure.authentication.mfa;

public class MfaRequiredException extends RuntimeException {

    public MfaRequiredException(String msg) {
        super(msg);
    }
}
