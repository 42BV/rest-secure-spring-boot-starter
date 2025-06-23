package nl._42.restsecure.autoconfigure.test;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import nl._42.restsecure.autoconfigure.authentication.AbstractRestAuthenticationSuccessHandler;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
public class RestAuthenticationSuccessHandlerConfig {

    public static final String AUTHENTICATION_SUCCESS_HEADER = "AuthenticationSuccessful";

    @Bean
    public <T extends RegisteredUser> AbstractRestAuthenticationSuccessHandler<T> successHandler() {
        return new AbstractRestAuthenticationSuccessHandler<>(null) {
            @Override
            protected void doHandle(HttpServletRequest request, HttpServletResponse response, RegisteredUser user) {
                response.setHeader(AUTHENTICATION_SUCCESS_HEADER, SecurityContextHolder.getContext().getAuthentication().getName());
            }
        };
    }
}
