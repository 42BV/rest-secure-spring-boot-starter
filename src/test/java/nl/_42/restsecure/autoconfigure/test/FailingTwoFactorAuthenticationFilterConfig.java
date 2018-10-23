package nl._42.restsecure.autoconfigure.test;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl._42.restsecure.autoconfigure.HttpSecurityCustomizer;
import nl._42.restsecure.autoconfigure.RestAuthenticationFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class FailingTwoFactorAuthenticationFilterConfig {

    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return http -> http.addFilterAfter(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
                throw new BadCredentialsException("You supplied the wrong two-factor authentication code.");
            }
        }, RestAuthenticationFilter.class);
    }
}
