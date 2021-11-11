package nl._42.restsecure.autoconfigure.authentication.mfa;

import nl._42.restsecure.autoconfigure.authentication.User;
import nl._42.restsecure.autoconfigure.authentication.UserWithPassword;

import org.junit.platform.commons.util.StringUtils;

public class UserWithMfa extends UserWithPassword {

  private final String secretKey;
  private final boolean mandatory;

  public UserWithMfa(String username, String password, String secretKey, boolean mandatory, String role) {
    super(username, password, role);
    this.secretKey = secretKey;
    this.mandatory = mandatory;
  }

  @Override
  public boolean isMfaConfigured() {
    return StringUtils.isNotBlank(secretKey);
  }

  @Override
  public boolean isMfaMandatory() {
    return mandatory;
  }

  @Override
  public String getMfaSecretKey() {
    return secretKey;
  }
}
