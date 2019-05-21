package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public class DefaultUserProvider implements UserProvider {

  @Override
  public RegisteredUser toUser(Authentication authentication) {
    return new RegisteredUser() {

      @Override
      public String getUsername() {
        return authentication.getName();
      }

      @Override
      public Set<String> getAuthorities() {
        return authentication.getAuthorities().stream()
                             .map(GrantedAuthority::getAuthority)
                             .collect(Collectors.toSet());
      }

    };
  }

}
