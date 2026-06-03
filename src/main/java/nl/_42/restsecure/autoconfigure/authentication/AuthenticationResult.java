package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Interface representing the json result object of the authentication endpoints.
 * The json object will by default have an 'authenticated' boolean, a 'username' string and an 'authorities' array property.
 * When no user is logged in, {@link #isAuthenticated()} returns {@code false} and the user-related fields are absent or {@code null}.
 */
public interface AuthenticationResult {

    @JsonProperty
    default boolean isAuthenticated() {
        return true;
    }

    @JsonProperty
    String getUsername();

    @JsonProperty
    Set<String> getAuthorities();
}
