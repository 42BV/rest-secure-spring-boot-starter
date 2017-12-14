package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

/**
 * Provide an implementation as {@link Bean} to the {@link ApplicationContext} to customize
 * the returned json of the default authentication endpoints.
 *
 * @param <T> your custom user type implementing {@link RegisteredUser}
 */
public interface AuthenticationResultProvider<T extends RegisteredUser> {

    /**
     * Translates the given {@link RegisteredUser} implementation to an {@link AuthenticationResult}.
     * 
     * @param user {@link RegisteredUser}
     * @return {@link AuthenticationResult}
     */
    AuthenticationResult toAuthenticationResult(T user);
}
