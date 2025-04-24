package nl._42.restsecure.autoconfigure.errorhandling;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaRequiredException;
import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.slf4j.Logger;

public class LogUtil {

    private LogUtil() {}

    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception) {
        // Filter out logs that are part of the login flow
        if (log.isDebugEnabled() || exception instanceof MfaRequiredException || form.username == null) {
            log.debug("Authentication failure for user '{}'! {}", form.username, exception.getMessage(), exception);
            return;
        }
        log.warn("Authentication failure for user '{}'! {}", form.username, exception.getMessage());
    }
}
