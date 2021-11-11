package nl._42.restsecure.autoconfigure.test;

import nl._42.restsecure.autoconfigure.HttpSecurityCustomizer;
import nl._42.restsecure.autoconfigure.authentication.InMemoryUserDetailService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupRequiredFilter;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MockMfaValidationService;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class MfaAuthenticationConfig {

    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return http -> http
                .addFilterBefore(mfaSetupRequiredFilter(), AnonymousAuthenticationFilter.class);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailService();
    }

    @Bean
    public MfaAuthenticationProvider mfaAuthenticationProvider(MfaValidationService mfaValidationService) {
        MfaAuthenticationProvider authenticationProvider = new MfaAuthenticationProvider();
        authenticationProvider.setMfaValidationService(mfaValidationService);
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        return authenticationProvider;
    }

    @Bean
    public MfaSetupRequiredFilter mfaSetupRequiredFilter() {
        MfaSetupRequiredFilter filter = new MfaSetupRequiredFilter();
        filter.setObjectMapper(new ObjectMapper());
        return filter;
    }
}
