package nl._42.restsecure.autoconfigure.test;

import java.util.Set;

import nl._42.restsecure.autoconfigure.authentication.AuthenticationResult;
import nl._42.restsecure.autoconfigure.authentication.AuthenticationResultProvider;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthenticationResultProviderConfig extends AbstractUserDetailsServiceConfig {

    @Bean
    public AuthenticationResultProvider<RegisteredUser> authenticationResultProvider() {
        return user -> new AuthenticationResult() {
            @Override
            public String getUsername() {
                return "customized";
            }
            @Override
            public Set<String> getAuthorities() {
                return user.getAuthorities();
            }
        };
    }

    @Override
    protected RegisteredUser foundUser() {
        return RegisteredUserBuilder.user().build();
    }
}
