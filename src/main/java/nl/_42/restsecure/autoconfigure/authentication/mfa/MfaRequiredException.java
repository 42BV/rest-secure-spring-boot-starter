package nl._42.restsecure.autoconfigure.authentication.mfa;

import org.springframework.security.authentication.InsufficientAuthenticationException;

public class MfaRequiredException extends InsufficientAuthenticationException {

    public MfaRequiredException(String msg) {
        super(msg);
    }

    public MfaRequiredException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
