package nl._42.restsecure.autoconfigure.components;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface AuthenticationResult {
   
    @JsonProperty
    RegisteredUserResult getCurrentUser();
        
    @JsonProperty
    String getCsrfToken();
}
