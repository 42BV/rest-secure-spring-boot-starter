package nl._42.restsecure.autoconfigure.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

/**
 * Provide an implementation as {@link Bean} to the {@link ApplicationContext} to customize
 * the returned JSON of the default authentication endpoints.
 */
public interface AuthenticationResultProvider<T extends RegisteredUser> {

    /**
     * Translates the given {@link RegisteredUser} implementation to an {@link AuthenticationResult}.
     *
     * @param request  {@link HttpServletRequest}
     * @param response {@link HttpServletResponse}
     * @param user     {@link RegisteredUser}
     * @return {@link AuthenticationResult}
     */
    AuthenticationResult toResult(HttpServletRequest request, HttpServletResponse response, T user);
}
