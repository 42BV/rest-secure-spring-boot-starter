package nl._42.restsecure.autoconfigure.components;

import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

public interface AuthenticationResultProvider<T extends RegisteredUser> {

    AbstractAuthenticationResult toAuthenticationResult(T user, String csrfToken);
}
