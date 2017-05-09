package nl._42.restsecure.autoconfigure.components;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface RegisteredUserResult {

    @JsonProperty
    String getUsername();
        
    @JsonProperty
    Set<String> getRoles();
}
