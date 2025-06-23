package nl._42.restsecure.autoconfigure.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Add an implementation of this class as @Bean to the ApplicationContext to be able to handle successful authentication.
 * This class helps in resolving the RegisteredUser from the Authentication object.
 * @param <T> the type of the implementation class of RegisteredUser
 */
@RequiredArgsConstructor
public abstract class AbstractRestAuthenticationSuccessHandler<T extends RegisteredUser> implements AuthenticationSuccessHandler {

    private final UserResolver<T> userResolver;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        doHandle(request, response, userResolver.resolve().orElseThrow(IllegalStateException::new));
    }

    protected abstract void doHandle(HttpServletRequest request, HttpServletResponse response, T user);
}
