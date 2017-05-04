package nl._42.restsecure.autoconfigure.components;

import static java.util.stream.Collectors.toSet;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

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
    private AuthenticationResultProvider<RegisteredUser> authenticationResultProvider;
    
    @RequestMapping(method = POST)
    AbstractAuthenticationResult<?> authenticate(@CurrentUser RegisteredUser user, CsrfToken csrfToken) {
        return getCurrentlyLoggedInUser(user, csrfToken);
    }

    @RequestMapping(path = "/current", method = RequestMethod.GET)
    AbstractAuthenticationResult<?> current(@CurrentUser RegisteredUser user, CsrfToken csrfToken) {
        return getCurrentlyLoggedInUser(user, csrfToken);
    }

    @RequestMapping(path = "/handshake", method = RequestMethod.GET)
    AbstractAuthenticationResult<?> handshake(CsrfToken csrfToken) {
        return new AbstractAuthenticationResult<AbstractUserResult>(csrfToken.getToken()) {};
    }
    
    private AbstractAuthenticationResult<?> getCurrentlyLoggedInUser(RegisteredUser user, CsrfToken csrfToken) {
        if (authenticationResultProvider != null) {
            return authenticationResultProvider.toAuthenticationResult(user, csrfToken.getToken());
        }
        AbstractUserResult userResult = new AbstractUserResult(user.getUsername(), user.getRolesAsString().stream().collect(toSet())) {};
        return new AbstractAuthenticationResult<AbstractUserResult>(userResult, csrfToken.getToken()) {};
    }
}
