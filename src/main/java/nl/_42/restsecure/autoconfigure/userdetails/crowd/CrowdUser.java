package nl._42.restsecure.autoconfigure.userdetails.crowd;

import static java.util.stream.Collectors.toList;
import static nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter.ROLE_PREFIX;
import static org.apache.commons.lang3.StringUtils.stripStart;

import java.util.Collections;
import java.util.List;

import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

public class CrowdUser implements RegisteredUser {

    private final String password;
    private final String username;
    private final List<String> roles;
    private String email;
    private String fullname;
    private String firstname;
    private String lastname;

    public CrowdUser(String username, String password, List<String> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public CrowdUser(CrowdUserDetails userDetails) {
        this(userDetails.getUsername(), "********", userDetails.getAuthorities()
                .stream()
                .map(ga -> stripStart(ga.getAuthority(), ROLE_PREFIX))
                .collect(toList()));
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
    public List<String> getRolesAsString() {
        return Collections.unmodifiableList(roles);
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }
}
