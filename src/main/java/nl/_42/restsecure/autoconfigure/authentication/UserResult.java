package nl._42.restsecure.autoconfigure.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public class UserResult implements AuthenticationResult {

    private final RegisteredUser user;

    public UserResult(RegisteredUser user) {
        this.user = user;
    }

    @Override
    @JsonProperty
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    @JsonProperty
    public Set<String> getAuthorities() {
        return user.getAuthorities();
    }

}
