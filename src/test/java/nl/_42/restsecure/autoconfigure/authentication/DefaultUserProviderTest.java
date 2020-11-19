package nl._42.restsecure.autoconfigure.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class DefaultUserProviderTest {

  private final UserProvider provider = new DefaultUserProvider();

  @Test
  public void to_user() {
    GrantedAuthority admin = new SimpleGrantedAuthority("admin");
    Authentication authentication = new UsernamePasswordAuthenticationToken("henk", "password", Collections.singleton(admin));

    RegisteredUser user = provider.toUser(authentication);
    assertEquals("henk", user.getUsername());
    assertEquals("", user.getPassword());
    assertEquals(Collections.singleton("admin"), user.getAuthorities());
    assertEquals(false, user.isAccountExpired());
    assertEquals(false, user.isAccountLocked());
    assertEquals(false, user.isCredentialsExpired());
    assertEquals(true, user.isEnabled());
  }

}
