package nl._42.restsecure.autoconfigure.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;

@Configuration
public class NullAuthenticationProviderConfig {

    @Bean
    public AuthenticationProvider crowdAuthenticationProvider() {
        return null;
    }
}
