package nl._42.restsecure.autoconfigure.test;

import nl._42.restsecure.autoconfigure.HttpSecurityCustomizer;
import nl._42.restsecure.autoconfigure.RequestAuthorizationCustomizer;
import nl._42.restsecure.autoconfigure.authentication.InMemoryUserDetailService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupRequiredFilter;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MockMfaValidationService;
import tools.jackson.databind.ObjectMapper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
public class MockMfaAuthenticationConfig {

    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return http -> http .addFilterBefore(mfaSetupRequiredFilter(null), AnonymousAuthenticationFilter.class);
    }

    @Bean
    public RequestAuthorizationCustomizer requestAuthorizationCustomizer() {
        return registry -> registry.requestMatchers("/users/**").permitAll();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailService();
    }

    @Bean
    public MfaValidationService mfaValidationService() {
        return new MockMfaValidationService();
    }

    @Bean
    public MfaAuthenticationProvider mfaAuthenticationProvider() {
        MfaAuthenticationProvider authenticationProvider = new MfaAuthenticationProvider(userDetailsService(), mfaValidationService());
        authenticationProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        return authenticationProvider;
    }

    @Bean
    public MfaSetupRequiredFilter mfaSetupRequiredFilter(ObjectMapper objectMapper) {
        MfaSetupRequiredFilter filter = new MfaSetupRequiredFilter();
        filter.setObjectMapper(objectMapper);
        return filter;
    }
}
