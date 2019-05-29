package nl._42.restsecure.autoconfigure.authentication;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.Assert.assertEquals;

public class UserDetailServiceTest {

  private InMemoryUserDetailService service;

  @Before
  public void setUp() {
    service = new InMemoryUserDetailService();
  }

  @Test
  public void loadUserByUsername_shouldSucceed() {
    User user = new User("henk", "admin");

    service.register(user);

    UserDetailsAdapter<User> details = service.loadUserByUsername("henk");
    assertEquals(user, details.getUser());
  }

  @Test(expected = UsernameNotFoundException.class)
  public void loadUserByUsername_unknownUser_shouldFail() {
    service.loadUserByUsername("unknown");
  }

}
