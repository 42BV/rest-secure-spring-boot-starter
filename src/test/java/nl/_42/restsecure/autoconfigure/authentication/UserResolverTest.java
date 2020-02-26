package nl._42.restsecure.autoconfigure.authentication;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class UserResolverTest {

  private final UserResolver resolver = new UserResolver(
    new DefaultUserProvider()
  );

  @Test
  public void resolve_null_shouldReturnNull() {
    assertEquals(null, resolver.resolve(null));
  }

  @Test
  public void resolve_adapter_shouldSucceed() {
    User user = new User("henk", "admin");
    Authentication authentication = new AuthenticationAdapter(user);

    assertEquals(user, resolver.resolve(authentication));
  }

  @Test
  public void resolve_authentication_shouldSucceed() {
    GrantedAuthority authority = new SimpleGrantedAuthority("admin");
    Authentication authentication = new UsernamePasswordAuthenticationToken("henk", "", Collections.singleton(authority));

    RegisteredUser user = resolver.resolve(authentication);
    assertEquals("henk", user.getUsername());
    assertEquals("", user.getPassword());
    assertEquals(Collections.singleton("admin"), user.getAuthorities());
  }

}
