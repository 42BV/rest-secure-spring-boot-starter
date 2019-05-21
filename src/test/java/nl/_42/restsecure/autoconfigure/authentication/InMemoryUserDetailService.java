package nl._42.restsecure.autoconfigure.authentication;

import java.util.HashMap;
import java.util.Map;

class InMemoryUserDetailService extends AbstractUserDetailsService<User> {

  private Map<String, User> users = new HashMap<>();

  void register(User user) {
    users.put(user.getUsername(), user);
  }

  @Override
  protected User findUserByUsername(String username) {
    return users.get(username);
  }

}
