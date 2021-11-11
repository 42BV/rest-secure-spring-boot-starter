package nl._42.restsecure.autoconfigure.authentication.mfa;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * An {@link UsernamePasswordAuthenticationToken} that also accepts a verification code (e.g. from an authenticator app).
 */
public class MfaAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String verificationCode;

    public MfaAuthenticationToken(Object principal, Object credentials, String verificationCode) {
        super(principal, credentials);
        this.verificationCode = verificationCode;
    }

    public String getVerificationCode() {
        return verificationCode;
    }
}
