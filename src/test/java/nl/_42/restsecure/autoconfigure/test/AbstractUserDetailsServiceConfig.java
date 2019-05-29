package nl._42.restsecure.autoconfigure.test;

import nl._42.restsecure.autoconfigure.authentication.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import org.springframework.context.annotation.Bean;

import java.util.Collections;
import java.util.Set;

public abstract class AbstractUserDetailsServiceConfig {

    @Bean
    public AbstractUserDetailsService<RegisteredUser> userDetailsService() {
        return new AbstractUserDetailsService<RegisteredUser>() {
            @Override
            public RegisteredUser findUserByUsername(String username) {
                return foundUser();
            }
        };
    }

    protected abstract RegisteredUser foundUser();

    public static final class RegisteredUserBuilder {

        boolean accountExpired;
        boolean accountLocked;
        boolean credentialsExpired;

        private RegisteredUserBuilder() {
        }

        public static RegisteredUserBuilder user() {
            return new RegisteredUserBuilder();
        }

        public RegisteredUserBuilder withAccountExpired(boolean expired) {
            this.accountExpired = expired;
            return this;
        }

        public RegisteredUserBuilder withAccountLocked(boolean locked) {
            this.accountLocked = locked;
            return this;
        }

        public RegisteredUserBuilder withCredentialsExpired(boolean expired) {
            this.credentialsExpired = expired;
            return this;
        }

        public RegisteredUser build() {
            return new RegisteredUser() {

                @Override
                public String getUsername() {
                    return "username";
                }

                @Override
                public String getPassword() {
                    return "password";
                }

                @Override
                public Set<String> getAuthorities() {
                    return Collections.singleton("ROLE_ADMIN");
                }

                @Override
                public boolean isAccountExpired() {
                    return accountExpired;
                }

                @Override
                public boolean isAccountLocked() {
                    return accountLocked;
                }

                @Override
                public boolean isCredentialsExpired() {
                    return credentialsExpired;
                }

            };
        }

    }

}
