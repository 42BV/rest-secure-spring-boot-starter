package nl._42.restsecure.autoconfigure.authentication.mfa;

import java.util.ArrayList;
import java.util.List;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeService;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * An {@link DaoAuthenticationProvider} that supports Multi-Factor authentication (MFA, 2FA) using Time-based One-Time-Password (TOTP)
 * or email-based verification codes.
 */
public class MfaAuthenticationProvider extends DaoAuthenticationProvider {

    public static final String SERVER_MFA_CODE_REQUIRED_ERROR = "SERVER.MFA_CODE_REQUIRED_ERROR";
    public static final String DETAILS_MFA_SETUP_REQUIRED = "DETAILS.MFA_SETUP_REQUIRED";

    private boolean customVerificationStepsRegistered = false;
    private List<MfaVerificationCheck> verificationChecks;
    private MfaValidationService mfaValidationService;
    private EmailCodeService emailCodeService;

    public void setVerificationChecks(List<MfaVerificationCheck> verificationChecks) {
        this.customVerificationStepsRegistered = true;
        this.verificationChecks = verificationChecks;
    }

    public void setMfaValidationService(MfaValidationService mfaValidationService) {
        this.mfaValidationService = mfaValidationService;
    }
    
    public void setEmailCodeService(EmailCodeService emailCodeService) {
        this.emailCodeService = emailCodeService;
    }

    @Override
    protected void doAfterPropertiesSet() {
        super.doAfterPropertiesSet();
        Assert.notNull(this.mfaValidationService, "A MfaValidationService must be set");
        if (!this.customVerificationStepsRegistered) {
            this.verificationChecks = List.of(new MfaTotpVerificationCheck(mfaValidationService));
        } else {
            Assert.isTrue(this.verificationChecks != null && !this.verificationChecks.isEmpty(), "At least one verification check must be provided");
            if (verificationChecks.stream().noneMatch(MfaTotpVerificationCheck.class::isInstance)) {
                verificationChecks = new ArrayList<>(verificationChecks); // Ensure we are a mutable list.
                verificationChecks.add(new MfaTotpVerificationCheck(mfaValidationService));
            }
        }
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        super.additionalAuthenticationChecks(userDetails, authentication);

        if (userDetails instanceof UserDetailsAdapter<? extends RegisteredUser> userDetailsAdapter) {
            RegisteredUser user = userDetailsAdapter.user();
            
            if (userDetailsAdapter.isMfaConfigured()) {
                MfaAuthenticationToken mfaAuthentication = (MfaAuthenticationToken) authentication;
                String verificationCode = mfaAuthentication.getVerificationCode();
                
                // For email MFA, send verification code if not provided
                if ((verificationCode == null || verificationCode.isEmpty()) && 
                    user.getMfaType() == MfaType.EMAIL && 
                    emailCodeService != null) {
                    
                    String email = user.getMfaEmail();
                    if (email != null && !email.isEmpty()) {
                        emailCodeService.generateAndSendCode(email);
                    }
                }
                
                executeMfaVerificationSteps(mfaAuthentication, userDetailsAdapter);
            } else if (userDetailsAdapter.isMfaMandatory()) {
                authentication.setDetails(DETAILS_MFA_SETUP_REQUIRED);
            }
        }
    }

    private void executeMfaVerificationSteps(MfaAuthenticationToken mfaAuthenticationToken, UserDetailsAdapter<? extends RegisteredUser> userDetailsAdapter) {
        // If no code supplied, indicate a code is needed.
        if (mfaAuthenticationToken.getVerificationCode() == null || mfaAuthenticationToken.getVerificationCode().isEmpty()) {
            throw new MfaRequiredException(SERVER_MFA_CODE_REQUIRED_ERROR);
        }
        boolean verificationSucceeded = false;
        for (MfaVerificationCheck verificationCheck : verificationChecks) {
            if (verificationCheck.validate(userDetailsAdapter.user(), mfaAuthenticationToken)) {
                verificationSucceeded = true;
                break;
            }
        }
        if (!verificationSucceeded) {
            throw new IllegalStateException(
                    "At least one verification check must either have succeeded or thrown an AuthenticationException. Check the verifications passed to .setVerificationChecks() for any unmatched scenarios.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MfaAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
