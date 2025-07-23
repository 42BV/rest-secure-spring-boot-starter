package nl._42.restsecure.autoconfigure.test;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import nl._42.restsecure.autoconfigure.authentication.AbstractRestAuthenticationSuccessHandler;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserResolver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
@RequiredArgsConstructor
public class RestAuthenticationSuccessHandlerConfig<T extends RegisteredUser> {

    public static final String AUTHENTICATION_SUCCESS_HEADER = "AuthenticationSuccessful";

    private final UserResolver<T> userResolver;

    @Bean
    public AbstractRestAuthenticationSuccessHandler<T> successHandler() {
        return new AbstractRestAuthenticationSuccessHandler<>(userResolver) {
            @Override
            protected void doHandle(HttpServletRequest request, HttpServletResponse response, RegisteredUser user) {
                response.setHeader(AUTHENTICATION_SUCCESS_HEADER, SecurityContextHolder.getContext().getAuthentication().getName());
            }
        };
    }
}
