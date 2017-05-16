package nl._42.restsecure.autoconfigure.components;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.csrf.CsrfToken;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

/**
 * Provide an implementation as {@link Bean} to the {@link ApplicationContext} to customize
 * the returned json of the default authentication endpoints.
 *
 * @param <T> your custom user type implementing {@link RegisteredUser}
 */
public interface AuthenticationResultProvider<T extends RegisteredUser> {

    /**
     * Translates the given {@link RegisteredUser} implementation and csrfToken to an {@link AuthenticationResult}.
     * 
     * @param user {@link RegisteredUser}
     * @param csrfToken {@link CsrfToken}
     * @return {@link AuthenticationResult}
     */
    AuthenticationResult toAuthenticationResult(T user, CsrfToken csrfToken);
}
