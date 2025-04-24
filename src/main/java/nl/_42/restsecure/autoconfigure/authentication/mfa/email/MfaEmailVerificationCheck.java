package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationToken;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaType;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaVerificationCheck;
import nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;

public class MfaEmailVerificationCheck implements MfaVerificationCheck {
    private final EmailCodeService emailCodeService;
    
    public MfaEmailVerificationCheck(EmailCodeService emailCodeService) {
        this.emailCodeService = emailCodeService;
    }
    
    @Override
    public boolean validate(RegisteredUser user, MfaAuthenticationToken authenticationToken) throws AuthenticationException {
        if (user.getMfaType() != MfaType.EMAIL) {
            return false; // Not applicable for this user
        }
        
        String code = authenticationToken.getVerificationCode();
        String email = user.getMfaEmail();
        
        if (email == null || email.isEmpty()) {
            throw new IllegalStateException("User has EMAIL MFA type but no email address configured");
        }
        
        if (!emailCodeService.verifyCode(email, code)) {
            throw new BadCredentialsException(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR);
        }
        
        return true;
    }
}