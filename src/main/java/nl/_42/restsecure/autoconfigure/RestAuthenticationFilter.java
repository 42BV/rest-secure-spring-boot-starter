package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpMethod.POST;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationToken;
import nl._42.restsecure.autoconfigure.errorhandling.LogUtil;
import nl._42.restsecure.autoconfigure.errorhandling.LoginAuthenticationExceptionHandler;
import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;
import nl._42.restsecure.autoconfigure.utils.FormUtil;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Handles the login POST request. Tries to Authenticate the given user credentials using the auto configured {@link AuthenticationManager}.
 * Expects the request body to contain json like:
 * <code>{ username: 'user@email.com', password: 'secret' }</code>
 * After a successful login, sets the read json as request attribute. This to enable subsequent {@link Filter}'s to obtain this information.
 */
@Setter
@Slf4j
@RequiredArgsConstructor
public class RestAuthenticationFilter extends OncePerRequestFilter {

    public static final String LOGIN_FORM_JSON = "loginFormJson";
    private static final AntPathRequestMatcher DEFAULT_MATCHER = new AntPathRequestMatcher("/authentication", POST.name());

    private final LoginAuthenticationExceptionHandler loginExceptionHandler;
    private final AuthenticationManager authenticationManager;

    private SecurityContextRepository securityContextRepository = new DelegatingSecurityContextRepository(new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());
    private RememberMeServices rememberMeServices = new NullRememberMeServices();
    private AuthenticationSuccessHandler successHandler = (request, response, authentication) -> {};
    private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (DEFAULT_MATCHER.matches(request)) {
            doLogin(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    private void doLogin(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);
        LoginForm form = formValues.form();
        AbstractAuthenticationToken token = new MfaAuthenticationToken(form.username, form.password, form.verificationCode);
        try {
            log.info("Authenticating user: {}", form.username);
            Authentication authentication = authenticationManager.authenticate(token);
            onAuthenticationSuccess(request, response, authentication, formValues);
            chain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            onAuthenticationFail(request, response, ex, form);
        }
    }

    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication, FormValues<LoginForm> formValues)
            throws IOException, ServletException {
        securityContextHolderStrategy.getContext().setAuthentication(authentication);
        securityContextRepository.saveContext(securityContextHolderStrategy.getContext(), request, response);
        sessionStrategy.onAuthentication(authentication, request, response);
        request.setAttribute(LOGIN_FORM_JSON, formValues.formJson());
        successHandler.onAuthenticationSuccess(request, response, authentication);
        if (formValues.form().rememberMe) {
            rememberMeServices.loginSuccess(request, response, authentication);
        }
    }

    private void onAuthenticationFail(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception, LoginForm form) throws IOException {
        LogUtil.logAuthenticationFailure(log, form, exception);
        securityContextHolderStrategy.clearContext();
        loginExceptionHandler.handle(request, response, exception);
        rememberMeServices.loginFail(request, response);
    }

}
