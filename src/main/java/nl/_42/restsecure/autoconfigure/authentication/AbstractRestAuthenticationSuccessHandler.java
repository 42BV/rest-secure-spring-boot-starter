package nl._42.restsecure.autoconfigure.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Add an implementation of this class as @Bean to the ApplicationContext to be able to handle successful authentication.
 * This class helps in resolving the RegisteredUser from the Authentication object.
 * @param <T> the type of the implementation class of RegisteredUser
 */
public abstract class AbstractRestAuthenticationSuccessHandler<T extends RegisteredUser> implements AuthenticationSuccessHandler {

    @Lazy
    @Autowired
    private UserResolver userResolver;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        doHandle(request, response, (T) userResolver.resolve(authentication));
    }

    protected abstract void doHandle(HttpServletRequest request, HttpServletResponse response, T user);
}
