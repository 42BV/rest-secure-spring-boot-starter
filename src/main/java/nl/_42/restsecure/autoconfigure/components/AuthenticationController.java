package nl._42.restsecure.autoconfigure.components;

import static java.util.stream.Collectors.toSet;
import static nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter.ROLE_PREFIX;
import static org.apache.commons.lang3.StringUtils.stripStart;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;
import nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter;

/**
 * This controller implements the default /authentication and /authentication/handshake endpoints.
 * Provide an implementation of {@link AuthenticationResultProvider} as {@link Bean} to the {@link ApplicationContext} to customize
 * the returned json.
 */
@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    @Autowired(required = false)
    private AuthenticationResultProvider authenticationResultProvider;
    
    @RequestMapping(method = POST)
    AuthenticationResult authenticate(@AuthenticationPrincipal(errorOnInvalidType = true) UserDetails userDetails, CsrfToken csrfToken) {
        return transform(userDetails, csrfToken);
    }

    @RequestMapping(path = "/current", method = RequestMethod.GET)
    AuthenticationResult current(@AuthenticationPrincipal(errorOnInvalidType = true) UserDetails userDetails, CsrfToken csrfToken) {
        return transform(userDetails, csrfToken);
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
    
    private AuthenticationResult transform(UserDetails userDetails, CsrfToken csrfToken) {
        if (authenticationResultProvider != null && userDetails instanceof UserDetailsAdapter<?>) {
            UserDetailsAdapter<RegisteredUser> userAdapter = (UserDetailsAdapter<RegisteredUser>)userDetails;
            return authenticationResultProvider.toAuthenticationResult(userAdapter.getUser(), csrfToken);
        }
        RegisteredUserResult userResult = new RegisteredUserResult() {
            @Override
            public String getUsername() {
                return userDetails.getUsername();
            }
            @Override
            public Set<String> getRoles() {
                return userDetails.getAuthorities()
                        .stream()
                        .map(auth -> stripStart(auth.getAuthority(), ROLE_PREFIX))
                        .collect(toSet());
            }};
        return new AuthenticationResult() {
            @Override
            public RegisteredUserResult getCurrentUser() {
                return userResult;
            }
            @Override
            public String getCsrfToken() {
                return csrfToken.getToken();
            }
        };
    }
}
