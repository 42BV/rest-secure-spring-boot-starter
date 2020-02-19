package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DefaultAuthenticationResultProviderTest {

  private final AuthenticationResultProvider provider = new DefaultAuthenticationResultProvider();

  @Test
  public void to_result() {
    User user = new User("henk", "admin");

    AuthenticationResult result = provider.toResult(null, null, user);
    assertEquals("henk", result.getUsername());
    assertEquals(user.getAuthorities(), result.getAuthorities());
  }

}
