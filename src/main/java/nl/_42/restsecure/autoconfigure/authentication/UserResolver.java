package nl._42.restsecure.autoconfigure.authentication;

import static java.util.Optional.ofNullable;
import static java.util.function.Predicate.not;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import java.util.Optional;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class UserResolver<T extends RegisteredUser> {

  private final UserProvider provider;

  public UserResolver(UserProvider provider) {
    this.provider = provider;
  }

  public Optional<T> resolve() {
    return ofNullable(getContext().getAuthentication())
            .filter(not(AnonymousAuthenticationToken.class::isInstance))
            .map(auth -> {
              if (auth.getPrincipal() instanceof UserDetailsAdapter) {
                return (T)((UserDetailsAdapter) auth.getPrincipal()).getUser();
              } else {
                return (T)provider.toUser(auth);
              }
            });
      }

}
