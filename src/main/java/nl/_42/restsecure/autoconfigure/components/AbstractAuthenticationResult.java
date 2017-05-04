package nl._42.restsecure.autoconfigure.components;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AbstractAuthenticationResult {

    private final AbstractUserResult currentUser;
    private final String csrfToken;
    
    AbstractAuthenticationResult(String csrfToken) {
        this(null, csrfToken);
    }

    protected AbstractAuthenticationResult(AbstractUserResult currentUser, String csrfToken) {
        this.currentUser = currentUser;
        this.csrfToken = csrfToken;
    }
    
    @JsonProperty
    public AbstractUserResult getCurrentUser() {
        return currentUser;
    }
    
    @JsonProperty
    public String getCsrfToken() {
        return csrfToken;
    }
}
