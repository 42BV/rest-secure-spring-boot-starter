package nl._42.restsecure.autoconfigure.userdetails.crowd;

import static java.util.stream.Collectors.toList;
import static nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter.ROLE_PREFIX;
import static org.apache.commons.lang3.StringUtils.stripStart;

import java.util.Collections;
import java.util.List;

import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

public class CrowdUser implements RegisteredUser {

    private final String username;
    private final String email;
    private final String fullname;
    private final String firstname;
    private final String lastname;
    private final List<String> roles;

    public CrowdUser(CrowdUserDetails userDetails) {
        this.username = userDetails.getUsername();
        this.email = userDetails.getEmail();
        this.firstname = userDetails.getFirstName();
        this.lastname = userDetails.getLastName();
        this.fullname = userDetails.getFullName();
        this.roles = userDetails.getAuthorities()
                .stream()
                .map(ga -> stripStart(ga.getAuthority(), ROLE_PREFIX))
                .collect(toList());
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return "********";
    }

    @Override
    public List<String> getRolesAsString() {
        return Collections.unmodifiableList(roles);
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
