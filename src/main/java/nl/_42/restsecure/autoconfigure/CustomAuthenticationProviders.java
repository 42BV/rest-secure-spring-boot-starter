package nl._42.restsecure.autoconfigure;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;

public interface CustomAuthenticationProviders {

    List<AuthenticationProvider> get();
}
