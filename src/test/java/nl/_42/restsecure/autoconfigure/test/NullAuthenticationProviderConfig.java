package nl._42.restsecure.autoconfigure.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationProvider;

@Configuration
public class NullAuthenticationProviderConfig {

    @Bean
    @Primary
    public AuthenticationProvider crowdAuthenticationProvider() {
        return null;
    }

}
