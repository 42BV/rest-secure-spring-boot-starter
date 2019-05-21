package nl._42.restsecure.autoconfigure.authentication;

import java.util.Collections;
import java.util.Set;

class User implements RegisteredUser {

  private final String username;
  private final String role;

  User(String username, String role) {
    this.username = username;
    this.role = role;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public Set<String> getAuthorities() {
    return Collections.singleton(role);
  }

}
