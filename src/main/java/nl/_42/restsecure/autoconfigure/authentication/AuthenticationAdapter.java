package nl._42.restsecure.autoconfigure.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * Authentication implementation that is based on a user object. The
 * principal is a user details adapter, containing the original user.
 */
public class AuthenticationAdapter extends UsernamePasswordAuthenticationToken {

  /**
   * Create a new authentication based on a user.
   * @param user the registered user
   */
  public AuthenticationAdapter(RegisteredUser user) {
    this(new UserDetailsAdapter(user));
  }

  private AuthenticationAdapter(UserDetailsAdapter details) {
    super(details,"", details.getAuthorities());
  }

}
