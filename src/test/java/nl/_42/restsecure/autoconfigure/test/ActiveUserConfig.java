package nl._42.restsecure.autoconfigure.test;

import static nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder.user;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import org.springframework.context.annotation.Configuration;

@Configuration
public class ActiveUserConfig extends AbstractUserDetailsServiceConfig {
    
    @Override
    protected RegisteredUser foundUser() {
        return user().build();
    }

}
