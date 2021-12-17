package nl._42.restsecure.autoconfigure.authentication.mfa;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;

public class MfaTotpVerificationCheck implements MfaVerificationCheck {

    private final MfaValidationService mfaValidationService;

    public MfaTotpVerificationCheck(MfaValidationService mfaValidationService) {
        this.mfaValidationService = mfaValidationService;
    }

    @Override
    public boolean validate(RegisteredUser user, MfaAuthenticationToken authenticationToken) throws AuthenticationException {
        // If no pre-authorized code assigned, validate the code supplied against the currently-valid TOTP code.
        if (!mfaValidationService.verifyMfaCode(user.getMfaSecretKey(), authenticationToken.getVerificationCode())) {
            throw new BadCredentialsException(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR);
        }

        return true;
    }
}
