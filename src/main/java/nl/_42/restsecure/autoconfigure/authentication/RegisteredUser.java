package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

import org.springframework.security.core.Authentication;

/**
 * Let your custom user object implement this interface.
 * This will be the object that is set as user on the {@link Authentication} principal.
 */
public interface RegisteredUser {

    String getUsername();

    default String getPassword() {
        return "";
    }

    Set<String> getAuthorities();

    default boolean isAccountExpired() {
        return false;
    }

    default boolean isAccountLocked() {
        return false;
    }

    default boolean isCredentialsExpired() {
        return false;
    }

    default boolean isEnabled() {
        return true;
    }

    default boolean isMfaConfigured() {
        return false;
    }

    default boolean isMfaMandatory() {
        return false;
    }

    default String getMfaSecretKey() {
        return null;
    }

    /**
     * A non-sensitive identifier of this user for the log, such as its technical id. A successful login is logged at
     * INFO as {@code Authentication succeeded for user <logId>}. The username is personal data (often an email
     * address) and is never logged at INFO or WARN. Never return the username or anything else that identifies a
     * person directly.
     *
     * @return the identifier, or {@code null} (the default) to log the login without a user
     */
    default String getLogId() {
        return null;
    }

}
