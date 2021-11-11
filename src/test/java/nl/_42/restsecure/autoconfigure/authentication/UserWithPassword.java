package nl._42.restsecure.autoconfigure.authentication;

import java.util.Collections;
import java.util.Set;

public class UserWithPassword extends User {

  private final String password;

  public UserWithPassword(String username, String password, String role) {
    super(username, role);
    this.password = password;
  }

  @Override
  public String getPassword() {
    return password;
  }

}
