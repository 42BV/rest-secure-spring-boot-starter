package nl._42.restsecure.autoconfigure.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This controller implements the default /authentication and /authentication/current endpoints.
 * Provide an implementation of {@link AuthenticationResultProvider} as {@link Bean} to the {@link ApplicationContext} to customize
 * the returned json.
 */
@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    private final AuthenticationResultProvider provider;

    public AuthenticationController(AuthenticationResultProvider provider) {
        this.provider = provider;
    }

    @PostMapping
    public AuthenticationResult authenticate(HttpServletRequest request,
            HttpServletResponse response, @CurrentUser RegisteredUser user) {
        return current(request, response, user);
    }

    @GetMapping("/current")
    public AuthenticationResult current(HttpServletRequest request, HttpServletResponse response, @CurrentUser RegisteredUser user) {
        return provider.toResult(request, response, user);
    }

}
