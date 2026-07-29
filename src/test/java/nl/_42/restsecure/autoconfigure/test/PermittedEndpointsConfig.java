package nl._42.restsecure.autoconfigure.test;

import nl._42.restsecure.autoconfigure.RequestAuthorizationCustomizer;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PermittedEndpointsConfig extends AbstractUserDetailsServiceConfig {

    @Bean
    public RequestAuthorizationCustomizer requestAuthorizationCustomizer() {
        return urlRegistry -> urlRegistry.requestMatchers("/test/**").permitAll();
    }

    @Override
    protected RegisteredUser foundUser() {
        return RegisteredUserBuilder.user().build();
    }
}
