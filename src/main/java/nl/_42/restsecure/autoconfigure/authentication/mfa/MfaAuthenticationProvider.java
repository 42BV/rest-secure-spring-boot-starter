package nl._42.restsecure.autoconfigure.authentication.mfa;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * An {@link DaoAuthenticationProvider} that supports Multi-Factor authentication (MFA, 2FA) using Time-based One-Time-Password (TOTP).
 */
public class MfaAuthenticationProvider extends DaoAuthenticationProvider {

    public static final String SERVER_MFA_CODE_REQUIRED_ERROR = "SERVER.MFA_CODE_REQUIRED_ERROR";
    public static final String DETAILS_MFA_SETUP_REQUIRED = "DETAILS.MFA_SETUP_REQUIRED";

    private MfaValidationService mfaValidationService;

    public void setMfaValidationService(MfaValidationService mfaValidationService) {
        this.mfaValidationService = mfaValidationService;
    }

    @Override
    protected void doAfterPropertiesSet() {
        super.doAfterPropertiesSet();
        Assert.notNull(this.mfaValidationService, "A MfaValidationService must be set");
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        super.additionalAuthenticationChecks(userDetails, authentication);

        if (userDetails instanceof UserDetailsAdapter) {
            UserDetailsAdapter<? extends RegisteredUser> userDetailsAdapter = (UserDetailsAdapter<?>) userDetails;

            if (userDetailsAdapter.isMfaConfigured()) {
                MfaAuthenticationToken mfaAuthenticationToken = (MfaAuthenticationToken) authentication;
                // If no code supplied, indicate a code is needed.
                if (mfaAuthenticationToken.getVerificationCode() == null || mfaAuthenticationToken.getVerificationCode().equals("")) {
                    throw new InsufficientAuthenticationException(SERVER_MFA_CODE_REQUIRED_ERROR);
                }
                // If invalid code supplied, authentication has failed.
                if (!mfaValidationService.verifyMfaCode(((UserDetailsAdapter<?>) userDetails).getUser().getMfaSecretKey(), mfaAuthenticationToken.getVerificationCode())) {
                    throw new BadCredentialsException(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR);
                }
                // If mfa is mandatory for this user, but not setup, indicate it must be setup first.
            } else if (userDetailsAdapter.isMfaMandatory()) {
                authentication.setDetails(DETAILS_MFA_SETUP_REQUIRED);
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MfaAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
