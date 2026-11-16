package nl._42.restsecure.autoconfigure.authentication;

import java.util.Optional;

/**
 * Optional bean that turns the username of a login attempt into a non-sensitive identifier for the log, such as the
 * technical id of the user. A username is personal data (often an email address), so it is never logged at INFO or
 * WARN. With this bean every attempt is logged at INFO as {@code Authenticating user <id>} (or
 * {@code an unknown user}), and a failure at WARN as {@code Authentication failure for user <id>}. Without it the
 * attempt is only logged at DEBUG, and the failure without a user.
 * <p>
 * It is called once per login attempt. Return an empty {@link Optional} when no user has this username. Never return
 * the username itself, a plain hash of it, or anything else that identifies a person directly.
 */
@FunctionalInterface
public interface LoginLogIdResolver {

    /**
     * @param username the username as it was entered in the login form, never {@code null}
     * @return a non-sensitive identifier of the user with this username, or empty when there is none
     */
    Optional<String> resolve(String username);
}
