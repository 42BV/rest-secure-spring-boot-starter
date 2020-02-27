package nl._42.restsecure.autoconfigure.authentication;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;

import java.util.Collections;
import java.util.Set;

public class User implements RegisteredUser {

  private final String username;
  private final String role;

  public User(String username, String role) {
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
