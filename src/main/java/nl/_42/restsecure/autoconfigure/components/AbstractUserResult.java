package nl._42.restsecure.autoconfigure.components;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AbstractUserResult {

    private final String username;
    private final Set<String> roles;
    
    protected AbstractUserResult(String username, Set<String> roles) {
        this.username = username;
        this.roles = roles;
    }
    
    @JsonProperty
    public String getUsername() {
        return username;
    }
    
    @JsonProperty
    public Set<String> getRoles() {
        return roles;
    }
}
