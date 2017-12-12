package nl._42.restsecure.autoconfigure.components;

import static java.util.Collections.singletonMap;

import java.util.Map;
import java.util.Set;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;
import nl._42.restsecure.autoconfigure.userdetails.crowd.CrowdUser;
import nl._42.restsecure.autoconfigure.userdetails.crowd.CrowdUserResult;

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

    @GetMapping("/handshake")
    Map<String, String> handshake(CsrfToken csrfToken) {
        return singletonMap("csrfToken", csrfToken.getToken());
    }
    
    private AuthenticationResult transform(RegisteredUser user) {
        if (authenticationResultProvider != null) {
            return authenticationResultProvider.toAuthenticationResult(user);
        }
        if (user instanceof CrowdUser) {
            return new CrowdUserResult((CrowdUser) user);
        }
        return new AuthenticationResult() {
            @Override
            @JsonProperty
            public String getUsername() {
                return user.getUsername();
            }
            @Override
            @JsonProperty
            public Set<String> getAuthorities() {
                return user.getAuthorities();
            }};
    }
}
