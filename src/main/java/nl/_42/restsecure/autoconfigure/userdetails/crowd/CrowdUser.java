package nl._42.restsecure.autoconfigure.userdetails.crowd;

import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;

import java.util.Set;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.springframework.security.core.GrantedAuthority;

import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;

public class CrowdUser implements RegisteredUser {

    private final String password;
    private final String username;
    private final Set<String> authorities;
    private String email;
    private String fullname;
    private String firstname;
    private String lastname;

    public CrowdUser(String username, String password, Set<String> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    public CrowdUser(CrowdUserDetails userDetails) {
        this(userDetails.getUsername(), "********", userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toSet()));
        this.email = userDetails.getEmail();
        this.firstname = userDetails.getFirstName();
        this.lastname = userDetails.getLastName();
        this.fullname = userDetails.getFullName();
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Set<String> getAuthorities() {
        return unmodifiableSet(authorities);
    }

    public String getEmail() {
        return email;
    }

    public String getFirstname() {
        return firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public String getFullname() {
        return fullname;
    }
}
