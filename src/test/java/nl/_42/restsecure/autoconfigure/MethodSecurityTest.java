package nl._42.restsecure.autoconfigure;

import nl._42.restsecure.autoconfigure.authentication.AuthenticationAdapter;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.User;
import nl._42.restsecure.autoconfigure.test.MethodSecurityConfig;
import nl._42.restsecure.autoconfigure.test.SecuredService;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.function.Supplier;

import static org.junit.Assert.assertTrue;

public class MethodSecurityTest extends AbstractApplicationContextTest {

  @Test
  public void everybody_shouldSucceed() {
    SecuredService securedService = getSecuredService();
    assertTrue(securedService.everybody());
  }

  @Test
  public void authenticated_shouldSucceed_whenLoggedIn() {
    SecuredService securedService = getSecuredService();

    User user = new User("user", "ROLE_user");
    assertTrue(runAs(user, securedService::authenticated));
  }

  @Test(expected = AuthenticationCredentialsNotFoundException.class)
  public void authenticated_shouldFail_whenAnonymous() {
    SecuredService securedService = getSecuredService();
    assertTrue(securedService.authenticated());
  }

  @Test
  public void admin_shouldSucceed_whenAdmin() {
    SecuredService securedService = getSecuredService();

    User admin = new User("admin", "ROLE_admin");
    assertTrue(runAs(admin, securedService::admin));
  }

  @Test(expected = AccessDeniedException.class)
  public void admin_shouldFail_whenUser() {
    SecuredService securedService = getSecuredService();

    User user = new User("user", "ROLE_user");
    assertTrue(runAs(user, securedService::admin));
  }

  @Test(expected = AuthenticationCredentialsNotFoundException.class)
  public void admin_shouldFail_whenAnonymous() {
    SecuredService securedService = getSecuredService();
    assertTrue(securedService.admin());
  }

  private <T> T runAs(RegisteredUser user, Supplier<T> supplier) {
    SecurityContext context = SecurityContextHolder.getContext();
    Authentication authentication = context.getAuthentication();

    try {
      context.setAuthentication(new AuthenticationAdapter(user));
      return supplier.get();
    } finally {
      context.setAuthentication(authentication);
    }
  }

  private SecuredService getSecuredService() {
    loadApplicationContext(MethodSecurityConfig.class);
    this.context.refresh();

    return context.getBean(SecuredService.class);
  }

}
