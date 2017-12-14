package nl._42.restsecure.autoconfigure.test;

import static nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder.user;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.springframework.context.annotation.Configuration;

@Configuration
public class CredentialsExpiredUserConfig extends AbstractUserDetailsServiceConfig {

    @Override
    protected RegisteredUser foundUser() {
        return user().withCredentialsExpired(true).build();
    }

}
