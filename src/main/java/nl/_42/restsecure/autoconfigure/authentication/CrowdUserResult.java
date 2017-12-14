package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

public class CrowdUserResult implements AuthenticationResult {

    public final String username;
    public final String email;
    public final String fullname;
    public final String firstname;
    public final String lastname;
    public final Set<String> authorities;

    public CrowdUserResult(CrowdUser user) {
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.fullname = user.getFullname();
        this.firstname = user.getFirstname();
        this.lastname = user.getLastname();
        this.authorities = user.getAuthorities();
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public Set<String> getAuthorities() {
        return authorities;
    }

}
