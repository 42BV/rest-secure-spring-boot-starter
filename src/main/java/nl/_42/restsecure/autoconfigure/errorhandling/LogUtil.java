package nl._42.restsecure.autoconfigure.errorhandling;

import static nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider.SERVER_MFA_CODE_REQUIRED_ERROR;

import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.slf4j.Logger;

public class LogUtil {

    private LogUtil() {}

    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception) {
        if (log.isDebugEnabled() || exception.getMessage().equals(SERVER_MFA_CODE_REQUIRED_ERROR)) {
            log.debug("Authentication failure for user '{}'! {}", form.username, exception.getMessage(), exception);
        } else {
            log.warn("Authentication failure for user '{}'! {}", form.username, exception.getMessage());
        }
    }
}
