package nl._42.restsecure.autoconfigure;

import lombok.RequiredArgsConstructor;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

@RequiredArgsConstructor
public class RestAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<RestAuthenticationFilterConfigurer<H>, H> {

    private final RestAuthenticationFilter authenticationFilter;
    private final RememberMeServices rememberMeServices;
    private final AuthenticationSuccessHandler successHandler;

    @Override
    public void configure(H http) {
        if (successHandler != null) {
            authenticationFilter.setSuccessHandler(successHandler);
        }
        if (rememberMeServices != null) {
            authenticationFilter.setRememberMeServices(rememberMeServices);
        }
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            authenticationFilter.setSessionStrategy(sessionAuthenticationStrategy);
        }
        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        if (securityContextRepository != null) {
            authenticationFilter.setSecurityContextRepository(securityContextRepository);
        }
        authenticationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
    }
}
