package nl._42.restsecure.autoconfigure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import nl._42.restsecure.autoconfigure.errorhandling.GenericErrorHandler;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * Handles the login POST request. Tries to Authenticate the given user credentials using the auto configured {@link AuthenticationManager}.
 * Expects the request body to contain json like:
 * <code>{ username: 'user@email.com', password: 'secret' }</code> 
 * After a successful login, sets the read json as request attribute. This to enable subsequent {@link Filter}'s to obtain this information.
 */
public class RestAuthenticationFilter extends OncePerRequestFilter {
    
    public static final String LOGIN_FORM_JSON = "loginFormJson";
    public static final String SERVER_LOGIN_FAILED_ERROR = "SERVER.LOGIN_FAILED_ERROR";

    private final Logger log = LoggerFactory.getLogger(RestAuthenticationFilter.class);
    
    private final GenericErrorHandler errorHandler;
    private final AntPathRequestMatcher requestMatcher;
    private final AuthenticationManager authenticationManager;
    private final RememberMeServices rememberMeServices;
    private final ObjectMapper objectMapper;

    public RestAuthenticationFilter(GenericErrorHandler handler, AuthenticationManager authenticationManager, RememberMeServices rememberMeServices) {
        this.errorHandler = handler;
        this.requestMatcher = new AntPathRequestMatcher("/authentication", POST.name());
        this.authenticationManager = authenticationManager;
        this.rememberMeServices = rememberMeServices;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (requestMatcher.matches(request)) {
            doLogin(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    private void doLogin(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String loginFormJson = IOUtils.toString(request.getReader());
        LoginForm form = objectMapper.readValue(loginFormJson, LoginForm.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(form.username, form.password);

        try {
            log.info("Authenticating user: {}", form.username);

            Authentication authentication = authenticationManager.authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.setAttribute(LOGIN_FORM_JSON, loginFormJson);

            if (rememberMeServices != null) {
                rememberMeServices.loginSuccess(request, response, authentication);
            }

            chain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            handleLoginFailure(request, response, ex);
        }
    }

    private void handleLoginFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        log.warn("Authentication failure: {}", exception.getMessage());

        SecurityContextHolder.getContext().setAuthentication(null);
        errorHandler.respond(response, UNAUTHORIZED, SERVER_LOGIN_FAILED_ERROR);

        if (rememberMeServices != null) {
            rememberMeServices.loginFail(request, response);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LoginForm {

        public String username;
        public String password;

    }

}
