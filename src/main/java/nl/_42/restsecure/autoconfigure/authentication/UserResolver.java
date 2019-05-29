package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class UserResolver {

  private final UserProvider provider;

  public UserResolver(UserProvider provider) {
    this.provider = provider;
  }

  public RegisteredUser resolve(Authentication authentication) {
    if (authentication == null) {
      return null;
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof UserDetailsAdapter) {
      return ((UserDetailsAdapter) principal).getUser();
    } else {
      return provider.toUser(authentication);
    }
  }

}
