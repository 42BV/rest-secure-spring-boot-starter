package nl._42.restsecure.autoconfigure.errorhandling;

import jakarta.servlet.http.HttpServletRequest;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaRequiredException;
import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.slf4j.Logger;

public class LogUtil {

    private LogUtil() {}

    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception) {
        logAuthenticationFailure(log, form, exception, null);
    }

    /**
     * Logs a failed authentication. Steps of the normal login flow and requests without a username go to DEBUG;
     * otherwise a WARN with the client address but without the username, which is personal data (often an e-mail
     * address). The DEBUG line keeps the username and the stacktrace.
     *
     * @param request the request, for the client address; may be {@code null}
     */
    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception, HttpServletRequest request) {
        // Filter out logs that are part of the login flow
        if (log.isDebugEnabled() || exception instanceof MfaRequiredException || form.username == null) {
            log.debug("Authentication failure for user '{}'! {}", form.username, exception.getMessage(), exception);
            return;
        }
        String from = request != null ? " from " + request.getRemoteAddr() : "";
        log.warn("Authentication failure{}! {}", from, exception.getMessage());
    }
}
