package nl._42.restsecure.autoconfigure.component;

import nl._42.restsecure.autoconfigure.iface.RegisteredUser;

public interface AuthenticationResultProvider {

    <T extends RegisteredUser> AbstractAuthenticationResult toAuthenticationResult(T user, String csrfToken);
}
