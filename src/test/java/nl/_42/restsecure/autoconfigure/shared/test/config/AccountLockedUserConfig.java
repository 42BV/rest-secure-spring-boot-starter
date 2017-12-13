package nl._42.restsecure.autoconfigure.shared.test.config;

import static nl._42.restsecure.autoconfigure.shared.test.config.AbstractUserDetailsServiceConfig.RegisteredUserBuilder.user;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.springframework.context.annotation.Configuration;

@Configuration
public class AccountLockedUserConfig extends AbstractUserDetailsServiceConfig {

    @Override
    protected RegisteredUser foundUser() {
        return user().withAccountLocked(true).build();
    }

}
