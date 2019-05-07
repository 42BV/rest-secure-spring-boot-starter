package nl._42.restsecure.autoconfigure.test;

import static java.util.Arrays.asList;

import nl._42.restsecure.autoconfigure.CustomAuthenticationProviders;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;
import com.atlassian.crowd.model.user.ImmutableUser;

@Configuration
public class MockedCrowdAuthenticationProviderConfig {

    @Bean
    public CustomAuthenticationProviders customAuthenticationProviders() {
        return () -> asList(new AuthenticationProvider() {

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                return new UsernamePasswordAuthenticationToken(
                        new CrowdUserDetails(
                                ImmutableUser.builder("crowdUser").build(),
                                asList(new SimpleGrantedAuthority("ROLE_USER"))),
                        "crowdPassword");
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return true;
            }

        });
    }
}
