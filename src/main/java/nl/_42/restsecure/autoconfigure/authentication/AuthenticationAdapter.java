package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class AuthenticationAdapter extends AbstractAuthenticationToken {

  private final UserDetailsAdapter<RegisteredUser> user;

  public AuthenticationAdapter(RegisteredUser user) {
    this(new UserDetailsAdapter<>(user));
  }

  private AuthenticationAdapter(UserDetailsAdapter<RegisteredUser> user) {
    super(user.getAuthorities());
    this.user = user;
  }

  @Override
  public Object getCredentials() {
    return "";
  }

  @Override
  public Object getPrincipal() {
    return user;
  }

}
