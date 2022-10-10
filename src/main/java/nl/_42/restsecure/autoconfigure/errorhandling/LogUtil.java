package nl._42.restsecure.autoconfigure.errorhandling;

import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.slf4j.Logger;

public class LogUtil {

    private LogUtil() {}

    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication failure for user '{}'! {}", form.username, exception.getMessage(), exception);
        } else {
            log.warn("Authentication failure for user '{}'! {}", form.username, exception.getMessage());
        }
    }
}
