package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.security.core.Authentication;

public interface UserProvider {

  RegisteredUser toUser(Authentication authentication);

}
