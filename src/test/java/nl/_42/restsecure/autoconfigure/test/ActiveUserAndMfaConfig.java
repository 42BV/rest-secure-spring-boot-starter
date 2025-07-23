package nl._42.restsecure.autoconfigure.test;

import static nl._42.restsecure.autoconfigure.test.AbstractUserDetailsServiceConfig.RegisteredUserBuilder.user;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ActiveUserAndMfaConfig extends AbstractUserDetailsServiceConfig {

    @Override
    protected RegisteredUser foundUser() {
        return user().build();
    }

    @Bean
    public MfaAuthenticationProvider mfaAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService,
            MfaValidationService mfaValidationService) {
        MfaAuthenticationProvider authenticationProvider = new MfaAuthenticationProvider(userDetailsService, mfaValidationService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }
}
