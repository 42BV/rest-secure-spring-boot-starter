package nl._42.restsecure.autoconfigure.authentication;

import static java.util.Collections.singletonMap;

import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonProperty;

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
    
    @PostMapping
    AuthenticationResult authenticate(@CurrentUser RegisteredUser user) {
        return transform(user);
    }

    @GetMapping("/current")
    AuthenticationResult current(@CurrentUser RegisteredUser user) {
        return transform(user);
    }

    private AuthenticationResult transform(RegisteredUser user) {
        AuthenticationResult authentication;
        if (authenticationResultProvider != null) {
            authentication = authenticationResultProvider.toAuthenticationResult(user);
        } else if (user instanceof CrowdUser) {
            authentication = new CrowdUserResult((CrowdUser) user);
        } else {
            authentication = new AuthenticationResult() {
                @Override
                @JsonProperty
                public String getUsername() {
                    return user.getUsername();
                }

                @Override
                @JsonProperty
                public Set<String> getAuthorities() {
                    return user.getAuthorities();
                }
            };
        }
        return authentication;
    }
}
