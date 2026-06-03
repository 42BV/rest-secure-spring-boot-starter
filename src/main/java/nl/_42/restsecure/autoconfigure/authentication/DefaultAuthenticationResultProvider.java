package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class DefaultAuthenticationResultProvider implements AuthenticationResultProvider<RegisteredUser> {

    @Override
    public AuthenticationResult toResult(HttpServletRequest request, HttpServletResponse response, RegisteredUser user) {
        if (user == null) {
            return new AuthenticationResult() {

                @Override
                public boolean isAuthenticated() {
                    return false;
                }

                @Override
                public String getUsername() {
                    return null;
                }

                @Override
                public Set<String> getAuthorities() {
                    return Set.of();
                }
            };
        }
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
