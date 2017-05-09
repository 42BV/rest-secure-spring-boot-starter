package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;

import nl._42.restsecure.autoconfigure.components.errorhandling.GenericErrorHandler;

public class RestAuthenticationFilter extends OncePerRequestFilter {

    public static final String LOGIN_FORM_JSON = "loginFormJson";
    private static final Logger LOGGER = LoggerFactory.getLogger(RestAuthenticationFilter.class);
    private static final String SERVER_LOGIN_FAILED_ERROR = "SERVER.LOGIN_FAILED_ERROR";

    private final GenericErrorHandler errorHandler;
    private final AntPathRequestMatcher matcher;
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;

    RestAuthenticationFilter(GenericErrorHandler errorHandler, AntPathRequestMatcher matcher, AuthenticationManager authenticationManager) {
        this.errorHandler = errorHandler;
        this.matcher = matcher;
        this.authenticationManager = authenticationManager;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (matcher.matches(request)) {
            String loginFormJson = IOUtils.toString(request.getReader());
            LoginForm form = objectMapper.readValue(loginFormJson, LoginForm.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(form.username, form.password);
            try {
                Authentication authentication = authenticationManager.authenticate(token);
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

    private void handleLoginFailure(HttpServletResponse response, AuthenticationException ae) throws IOException {
        errorHandler.respond(response, UNAUTHORIZED, SERVER_LOGIN_FAILED_ERROR);
        LOGGER.warn("Login failure", ae.getMessage());
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LoginForm {
        public String username;
        public String password;
    }
}
