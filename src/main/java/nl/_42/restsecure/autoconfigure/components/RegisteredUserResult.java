package nl._42.restsecure.autoconfigure.components;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Interface representing the 'currentUser' json object within the result of the authentication endpoints. 
 * The json object will have a 'username'string and a 'roles' array property.
 */
public interface RegisteredUserResult {

    @JsonProperty
    String getUsername();
        
    @JsonProperty
    Set<String> getRoles();
}
