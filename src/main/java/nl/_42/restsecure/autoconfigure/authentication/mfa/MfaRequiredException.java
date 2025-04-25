package nl._42.restsecure.autoconfigure.authentication.mfa;

import org.springframework.security.core.AuthenticationException;

public class MfaRequiredException extends AuthenticationException {

    public MfaRequiredException(String msg) {
        super(msg);
    }
}
