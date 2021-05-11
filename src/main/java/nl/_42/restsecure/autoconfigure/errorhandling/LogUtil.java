package nl._42.restsecure.autoconfigure.errorhandling;

import org.slf4j.Logger;

public class LogUtil {

    private LogUtil() {}

    public static void logAuthenticationFailure(Logger log, RuntimeException exception) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication failure! {}", exception.getMessage(), exception);
        } else {
            log.info("Authentication failure! {}", exception.getMessage());
        }
    }
}
