package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaType;
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
    
    default MfaType getMfaType() {
        return isMfaConfigured() ? MfaType.TOTP : MfaType.NONE;
    }
    
    default String getMfaEmail() {
        return null;
    }

}
