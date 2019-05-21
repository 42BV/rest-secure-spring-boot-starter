package nl._42.restsecure.autoconfigure.authentication;

import java.util.Set;

public class DefaultAuthenticationResultProvider implements AuthenticationResultProvider<RegisteredUser> {

  @Override
  public AuthenticationResult toResult(RegisteredUser user) {
    return new AuthenticationResult() {

      @Override
      public String getUsername() {
        return user.getUsername();
      }

      @Override
      public Set<String> getAuthorities() {
        return user.getAuthorities();
      }

    };
  }

}
