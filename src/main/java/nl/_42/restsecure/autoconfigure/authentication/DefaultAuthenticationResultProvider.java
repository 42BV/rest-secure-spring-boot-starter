package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DefaultAuthenticationResultProvider implements AuthenticationResultProvider<RegisteredUser> {

    @Override
    public AuthenticationResult toResult(HttpServletRequest request, HttpServletResponse response, RegisteredUser user) {
        return new AuthenticationResult() {

            @Override
            public String getUsername() {
                return user.getUsername();
            }

            @Override
            public Set<String> getAuthorities() {
                return user.getAuthorities();
            }
        };
    }
}
