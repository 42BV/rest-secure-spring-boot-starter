package nl._42.restsecure.autoconfigure.components;

import org.springframework.security.web.csrf.CsrfToken;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

public interface AuthenticationResultProvider<T extends RegisteredUser> {

    AuthenticationResult toAuthenticationResult(T user, CsrfToken csrfToken);
}
