package nl._42.restsecure.autoconfigure.components;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    @Autowired(required = false)
    private AuthenticationResultProvider authenticationResultProvider;
    
    @RequestMapping(method = POST)
    AuthenticationResult authenticate(@CurrentUser RegisteredUser user, CsrfToken csrfToken) {
        return getCurrentlyLoggedInUser(user, csrfToken);
    }

    @RequestMapping(path = "/current", method = RequestMethod.GET)
    AuthenticationResult current(@CurrentUser RegisteredUser user, CsrfToken csrfToken) {
        return getCurrentlyLoggedInUser(user, csrfToken);
    }

    @RequestMapping(path = "/handshake", method = RequestMethod.GET)
    AuthenticationResult handshake(CsrfToken csrfToken) {
        return new AuthenticationResult() {
            @Override
            public RegisteredUserResult getCurrentUser() {
                return null;
            }
            @Override
            public String getCsrfToken() {
                return csrfToken.getToken();
            }};
    }
    
    private AuthenticationResult getCurrentlyLoggedInUser(RegisteredUser user, CsrfToken csrfToken) {
        if (authenticationResultProvider != null) {
            return authenticationResultProvider.toAuthenticationResult(user, csrfToken);
        }
        RegisteredUserResult userResult = new RegisteredUserResult() {
            @Override
            public String getUsername() {
                return user.getUsername();
            }
            @Override
            public Set<String> getRoles() {
                return new HashSet<>(user.getRolesAsString());
            }};
        return new AuthenticationResult() {
            @Override
            public RegisteredUserResult getCurrentUser() {
                return userResult;
            }
            @Override
            public String getCsrfToken() {
                return csrfToken.getToken();
            }};
    }
}
