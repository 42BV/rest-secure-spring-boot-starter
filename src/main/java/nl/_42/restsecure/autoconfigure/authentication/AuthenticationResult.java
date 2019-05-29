package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Interface representing the json result object of the authentication endpoints. 
 * The json object will by default have a 'username' string and a 'roles' array property.
 */
public interface AuthenticationResult {

    @JsonProperty
    String getUsername();

    @JsonProperty
    Set<String> getAuthorities();

}
