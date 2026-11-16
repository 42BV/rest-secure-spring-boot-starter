package nl._42.restsecure.autoconfigure.errorhandling;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

import nl._42.restsecure.autoconfigure.authentication.LoginLogIdResolver;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaRequiredException;
import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.slf4j.Logger;

public class LogUtil {

    private LogUtil() {}

    /**
     * Logs a failed authentication without the username, which is personal data (often an email address).
     *
     * @see #logAuthenticationFailure(Logger, LoginForm, RuntimeException, HttpServletRequest, LoginLogIdResolver)
     */
    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception) {
        logAuthenticationFailure(log, form, exception, null, null);
    }

    /**
     * Logs a failed authentication. Steps of the normal login flow (MFA code still required) and requests without a
     * username go to DEBUG. Otherwise the failure is logged at WARN with the client address and, when a
     * {@link LoginLogIdResolver} is given, the identifier it returns for the username; never with the username itself.
     * The DEBUG line keeps the username and the stacktrace.
     *
     * @param log       the logger of the caller
     * @param form      the login form of the request
     * @param exception the reason the authentication failed
     * @param request   the request, for the client address; may be {@code null}
     * @param resolver  turns the username into a non-sensitive identifier; may be {@code null}
     */
    public static <T extends LoginForm> void logAuthenticationFailure(Logger log, T form, RuntimeException exception,
            HttpServletRequest request, LoginLogIdResolver resolver) {
        // Filter out logs that are part of the login flow
        if (log.isDebugEnabled() || exception instanceof MfaRequiredException || form.username == null) {
            log.debug("Authentication failure for user '{}'! {}", form.username, exception.getMessage(), exception);
            return;
        }
        String from = request != null ? " from " + request.getRemoteAddr() : "";
        if (resolver == null) {
            log.warn("Authentication failure{}! {}", from, exception.getMessage());
            return;
        }
        Optional<String> id = resolve(log, resolver, form.username);
        if (id.isPresent()) {
            log.warn("Authentication failure for user {}{}! {}", id.get(), from, exception.getMessage());
        } else {
            log.warn("Authentication failure for an unknown user{}! {}", from, exception.getMessage());
        }
    }

    /**
     * Resolves the log id of a username with the given resolver, without ever throwing: logging must never break the
     * handling of a login.
     *
     * @return the id, or empty when there is no resolver, no username, no user with this username, or the resolver failed
     */
    public static Optional<String> resolveLogId(Logger log, LoginLogIdResolver resolver, String username) {
        if (resolver == null || username == null) {
            return Optional.empty();
        }
        return resolve(log, resolver, username);
    }

    private static Optional<String> resolve(Logger log, LoginLogIdResolver resolver, String username) {
        try {
            return Optional.ofNullable(resolver.resolve(username)).flatMap(id -> id);
        } catch (RuntimeException e) {
            // Logging must never break the handling of a failed login.
            log.debug("LoginLogIdResolver failed; logging the failure without a user", e);
            return Optional.empty();
        }
    }
}
