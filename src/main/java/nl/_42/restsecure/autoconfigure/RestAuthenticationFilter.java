package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpMethod.POST;

import java.io.IOException;
import java.io.Reader;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl._42.restsecure.autoconfigure.authentication.AbstractRestAuthenticationSuccessHandler;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationToken;
import nl._42.restsecure.autoconfigure.errorhandling.LogUtil;
import nl._42.restsecure.autoconfigure.errorhandling.LoginAuthenticationExceptionHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Handles the login POST request. Tries to Authenticate the given user credentials using the auto configured {@link AuthenticationManager}.
 * Expects the request body to contain json like:
 * <code>{ username: 'user@email.com', password: 'secret' }</code>
 * After a successful login, sets the read json as request attribute. This to enable subsequent {@link Filter}'s to obtain this information.
 */
public class RestAuthenticationFilter extends OncePerRequestFilter {

    public static final String LOGIN_FORM_JSON = "loginFormJson";

    private final Logger log = LoggerFactory.getLogger(RestAuthenticationFilter.class);

    private final LoginAuthenticationExceptionHandler loginExceptionHandler;
    private final AntPathRequestMatcher requestMatcher;
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;
    private Optional<RememberMeServices> rememberMeServices = Optional.empty();
    private Optional<AbstractRestAuthenticationSuccessHandler> successHandler = Optional.empty();

    public RestAuthenticationFilter(LoginAuthenticationExceptionHandler loginExceptionHandler,
            AuthenticationManager authenticationManager) {
        this.loginExceptionHandler = loginExceptionHandler;
        this.requestMatcher = new AntPathRequestMatcher("/authentication", POST.name());
        this.authenticationManager = authenticationManager;
        this.objectMapper = new ObjectMapper();
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = Optional.ofNullable(rememberMeServices);
    }

    public void setAuthenticationSuccessHandler(AbstractRestAuthenticationSuccessHandler successHandler) {
        this.successHandler = Optional.ofNullable(successHandler);
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
        String loginFormJson = read(request);
        LoginForm form = objectMapper.readValue(loginFormJson, LoginForm.class);
        AbstractAuthenticationToken token = new MfaAuthenticationToken(form.username, form.password, form.verificationCode);

        try {
            log.info("Authenticating user: {}", form.username);

            Authentication authentication = authenticationManager.authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.setAttribute(LOGIN_FORM_JSON, loginFormJson);

            successHandler.ifPresent(sh -> sh.onAuthenticationSuccess(request, response, authentication));
            if (form.rememberMe) {
                rememberMeServices.ifPresent(rms -> rms.loginSuccess(request, response, authentication));
            }

            chain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            handleLoginFailure(request, response, ex);
        }
    }

    private String read(HttpServletRequest request) {
        try (Reader reader = request.getReader()) {
            StringBuilder builder = new StringBuilder();
            int result;
            while ((result = reader.read()) != -1) {
                builder.append((char) result);
            }
            return builder.toString();
        } catch (IOException ioe) {
            throw new IllegalStateException("Could not use reader", ioe);
        }
    }

    private void handleLoginFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        LogUtil.logAuthenticationFailure(log, exception);
        SecurityContextHolder.getContext().setAuthentication(null);
        loginExceptionHandler.handle(request, response, exception);
        rememberMeServices.ifPresent(rms -> rms.loginFail(request, response));
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LoginForm {

        public String username;
        public String password;
        public boolean rememberMe;
        public String verificationCode;

    }

}
