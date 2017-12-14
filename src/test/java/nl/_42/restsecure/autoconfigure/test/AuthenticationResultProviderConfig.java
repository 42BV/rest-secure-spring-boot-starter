package nl._42.restsecure.autoconfigure.test;

import java.util.Set;

import nl._42.restsecure.autoconfigure.authentication.AuthenticationResult;
import nl._42.restsecure.autoconfigure.authentication.AuthenticationResultProvider;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthenticationResultProviderConfig {

    @Bean
    public AuthenticationResultProvider<RegisteredUser> authenticationResultProvider() {
        return new AuthenticationResultProvider<RegisteredUser>() {
            @Override
            public AuthenticationResult toAuthenticationResult(RegisteredUser user) {
                return new AuthenticationResult() {                        
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
        };
    }
}
