package nl._42.restsecure.autoconfigure.userdetails;

import java.util.List;

import org.springframework.security.core.Authentication;

/**
 * Let your custom user object implement this interface.
 * This will be the object that is set as user on the {@link Authentication} principal.
 */
public interface RegisteredUser {

    String getUsername();
    
    String getPassword();
    
    List<String> getRolesAsString();
    
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
}
