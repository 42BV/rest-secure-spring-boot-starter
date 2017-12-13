package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl._42.restsecure.autoconfigure.components.errorhandling.GenericErrorHandler;
import nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.userdetails.crowd.CrowdUser;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Handles the login POST request. Tries to Authenticate the given user credentials using the auto configured {@link AuthenticationManager}.
 * Expects the request body to contain json like:
 * <code>{ username: 'user@email.com', password: 'secret' }</code> 
 * 
 * After a successful login, sets the read json as request attribute. This to enable subsequent {@link Filter}'s to obtain this information.
 */
public class RestAuthenticationFilter extends OncePerRequestFilter {
    
    public static final String LOGIN_FORM_JSON = "loginFormJson";
    public static final String SERVER_LOGIN_FAILED_ERROR = "SERVER.LOGIN_FAILED_ERROR";

    private final Logger log = LoggerFactory.getLogger(RestAuthenticationFilter.class);
    
    private final GenericErrorHandler errorHandler;
    private final AntPathRequestMatcher matcher;
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;

    RestAuthenticationFilter(GenericErrorHandler errorHandler, AntPathRequestMatcher matcher, AuthenticationManager authenticationManager) {
        this.errorHandler = errorHandler;
        this.matcher = matcher;
        this.authenticationManager = authenticationManager;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (matcher.matches(request)) {
            String loginFormJson = IOUtils.toString(request.getReader());
            LoginForm form = objectMapper.readValue(loginFormJson, LoginForm.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(form.username, form.password);
            try {
                log.info("Authenticating user: {}", form.username);
                Authentication authentication = authenticationManager.authenticate(token);
                authentication = convertIfNecessary(authentication);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                request.setAttribute(LOGIN_FORM_JSON, loginFormJson);
                chain.doFilter(request, response);
            } catch (AuthenticationException ex) {
                handleLoginFailure(response, ex);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    private Authentication convertIfNecessary(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof UserDetailsAdapter<?>)) {
            log.info("Converting the Authentication principal to UserDetailsAdapter to enable @CurrentUser annotation.");
            CrowdUserDetails crowdUserDetails = (CrowdUserDetails) authentication.getPrincipal();
            return new UsernamePasswordAuthenticationToken(
                    new UserDetailsAdapter<CrowdUser>(new CrowdUser(crowdUserDetails)),
                    authentication.getCredentials(),
                    authentication.getAuthorities());
        }
        return authentication;
    }

    private void handleLoginFailure(HttpServletResponse response, AuthenticationException ae) throws IOException {
        errorHandler.respond(response, UNAUTHORIZED, SERVER_LOGIN_FAILED_ERROR);
        log.warn("Authentication failure: {}", ae.getMessage());
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LoginForm {
        public String username;
        public String password;
    }
}
