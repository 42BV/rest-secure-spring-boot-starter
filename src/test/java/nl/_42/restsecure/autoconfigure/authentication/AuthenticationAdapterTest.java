package nl._42.restsecure.autoconfigure.authentication;

import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class AuthenticationAdapterTest {

  @Test
  public void getCredentials_shouldAlwaysBeEmpty() {
    User user = new User("henk", "admin");

    Authentication authentication = new AuthenticationAdapter(user);
    assertEquals("", authentication.getCredentials());
  }

  @Test
  public void getAuthorities_shouldSucceed() {
    User user = new User("henk", "admin");

    Authentication authentication = new AuthenticationAdapter(user);
    assertEquals(Collections.singletonList(
      new SimpleGrantedAuthority("admin")
    ), authentication.getAuthorities());
  }

  @Test
  public void getPrincipal_shouldSucceed() {
    User user = new User("henk", "admin");

    Authentication authentication = new AuthenticationAdapter(user);
    Object principal = authentication.getPrincipal();

    assertEquals(UserDetailsAdapter.class, principal.getClass());
    assertEquals(user, ((UserDetailsAdapter<?>) principal).getUser());
  }

}
