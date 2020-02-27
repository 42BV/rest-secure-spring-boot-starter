package nl._42.restsecure.autoconfigure.authentication;

import nl._42.restsecure.autoconfigure.authentication.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.authentication.User;

import java.util.HashMap;
import java.util.Map;

public class InMemoryUserDetailService extends AbstractUserDetailsService<User> {

  private Map<String, User> users = new HashMap<>();

  public void register(User user) {
    users.put(user.getUsername(), user);
  }

  @Override
  protected User findUserByUsername(String username) {
    return users.get(username);
  }

}
