package nl._42.restsecure.autoconfigure;

import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;

/**
 * Implement this interface and add it to the {@link ApplicationContext} to add custom {@link AuthenticationProvider}'s to the ßSpring Security web config.
 */
public interface CustomAuthenticationProviders {

    List<AuthenticationProvider> get();
}
