package nl._42.restsecure.autoconfigure.components;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Interface representing the json result of the authentication endpoints. 
 * The json object will have a 'currentUser' object and a 'csrfToken' string property.
 * 
 * @see RegisteredUserResult
 */
public interface AuthenticationResult {
   
    @JsonProperty
    RegisteredUserResult getCurrentUser();
        
    @JsonProperty
    String getCsrfToken();
}
