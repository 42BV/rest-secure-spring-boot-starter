package nl._42.restsecure.autoconfigure.test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl._42.restsecure.autoconfigure.authentication.AbstractRestAuthenticationSuccessHandler;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RestAuthenticationSuccessHandlerConfig {

    public static final String AUTHENTICATION_SUCCESS_HEADER = "AuthenticationSuccessful";

    @Bean
    public AbstractRestAuthenticationSuccessHandler successHandler() {
        return new AbstractRestAuthenticationSuccessHandler() {
            @Override
            protected void doHandle(HttpServletRequest request, HttpServletResponse response, RegisteredUser user) {
                response.setHeader(AUTHENTICATION_SUCCESS_HEADER, user.getUsername());
            }
        };
    }
}
