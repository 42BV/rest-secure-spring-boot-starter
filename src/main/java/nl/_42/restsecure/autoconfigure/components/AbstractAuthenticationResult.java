package nl._42.restsecure.autoconfigure.components;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AbstractAuthenticationResult<T> {

    private final T currentUser;
    private final String csrfToken;
    
    protected AbstractAuthenticationResult(String csrfToken) {
        this(null, csrfToken);
    }

    protected AbstractAuthenticationResult(T currentUser, String csrfToken) {
        this.currentUser = currentUser;
        this.csrfToken = csrfToken;
    }
    
    @JsonProperty
    public T getCurrentUser() {
        return currentUser;
    }
    
    @JsonProperty
    public String getCsrfToken() {
        return csrfToken;
    }
}
