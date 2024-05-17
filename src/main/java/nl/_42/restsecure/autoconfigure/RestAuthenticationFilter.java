package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpMethod.POST;

import java.io.IOException;
import java.util.Optional;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import nl._42.restsecure.autoconfigure.authentication.AbstractRestAuthenticationSuccessHandler;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationToken;
import nl._42.restsecure.autoconfigure.errorhandling.LogUtil;
import nl._42.restsecure.autoconfigure.errorhandling.LoginAuthenticationExceptionHandler;
import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;
import nl._42.restsecure.autoconfigure.utils.CachedBodyHttpServletRequest;
import nl._42.restsecure.autoconfigure.utils.FormUtil;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Handles the login POST request. Tries to Authenticate the given user credentials using the auto configured {@link AuthenticationManager}.
 * Expects the request body to contain json like:
 * <code>{ username: 'user@email.com', password: 'secret' }</code>
 * After a successful login, sets the read json as request attribute. This to enable subsequent {@link Filter}'s to obtain this information.
 */
@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    public static final String LOGIN_FORM_JSON = "loginFormJson";

    private static final AntPathRequestMatcher DEFAULT_MATCHER = new AntPathRequestMatcher("/authentication", POST.name());

    private final LoginAuthenticationExceptionHandler loginExceptionHandler;
    private final SecurityContextRepository securityContextRepository;
    private final AuthenticationManager authenticationManager;
    private final RequestMatcher requestMatcher;

    private Optional<RememberMeServices> rememberMeServices = Optional.empty();
    private Optional<AbstractRestAuthenticationSuccessHandler> successHandler = Optional.empty();

    /**
     * Creates an authentication filter with a default Ant path matcher on POST /authentication and a default ObjectMapper.
     *
     * @param loginExceptionHandler handler method for when exceptions occur
     * @param authenticationManager authentication manager
     */
    public RestAuthenticationFilter(
            LoginAuthenticationExceptionHandler loginExceptionHandler,
            SecurityContextRepository securityContextRepository,
            AuthenticationManager authenticationManager) {
        this(loginExceptionHandler, securityContextRepository, authenticationManager, DEFAULT_MATCHER);
    }

    /**
     * Creates an authentication filter where you can specify the request matcher and ObjectMapper.
     *
     * @param loginExceptionHandler handler method for when exceptions occur
     * @param authenticationManager authentication manager
     * @param requestMatcher        request matcher to test if the filter should be applied
     */
    public RestAuthenticationFilter(
            LoginAuthenticationExceptionHandler loginExceptionHandler,
            SecurityContextRepository securityContextRepository,
            AuthenticationManager authenticationManager,
            RequestMatcher requestMatcher
    ) {
        this.loginExceptionHandler = loginExceptionHandler;
        this.securityContextRepository = securityContextRepository;
        this.authenticationManager = authenticationManager;
        this.requestMatcher = requestMatcher;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = Optional.ofNullable(rememberMeServices);
    }

    public void setAuthenticationSuccessHandler(AbstractRestAuthenticationSuccessHandler<?> successHandler) {
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
        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(cachedRequest, LoginForm.class);
        LoginForm form = formValues.form();
        AbstractAuthenticationToken token = new MfaAuthenticationToken(form.username, form.password, form.verificationCode);

        try {
            log.info("Authenticating user: {}", form.username);

            Authentication authentication = authenticationManager.authenticate(token);
            setAuthentication(cachedRequest, response, authentication);

            cachedRequest.setAttribute(LOGIN_FORM_JSON, formValues.formJson());

            successHandler.ifPresent(sh -> sh.onAuthenticationSuccess(cachedRequest, response, authentication));
            if (form.rememberMe) {
                rememberMeServices.ifPresent(rms -> rms.loginSuccess(cachedRequest, response, authentication));
            }

            chain.doFilter(cachedRequest, response);
        } catch (AuthenticationException ex) {
            onException(cachedRequest, response, ex, form);
        }
    }

    private void setAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(authentication);
        securityContextRepository.saveContext(context, request, response);
    }

    private void onException(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception, LoginForm form) throws IOException {
        LogUtil.logAuthenticationFailure(log, form, exception);
        setAuthentication(request, response, null);
        loginExceptionHandler.handle(request, response, exception);
        rememberMeServices.ifPresent(rms -> rms.loginFail(request, response));
    }

}
