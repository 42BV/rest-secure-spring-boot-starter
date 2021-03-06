package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import nl._42.restsecure.autoconfigure.authentication.AbstractRestAuthenticationSuccessHandler;
import nl._42.restsecure.autoconfigure.authentication.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.authentication.AuthenticationController;
import nl._42.restsecure.autoconfigure.authentication.AuthenticationResultProvider;
import nl._42.restsecure.autoconfigure.authentication.DefaultAuthenticationResultProvider;
import nl._42.restsecure.autoconfigure.authentication.DefaultUserProvider;
import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserProvider;
import nl._42.restsecure.autoconfigure.errorhandling.DefaultLoginAuthenticationExceptionHandler;
import nl._42.restsecure.autoconfigure.errorhandling.GenericErrorHandler;
import nl._42.restsecure.autoconfigure.errorhandling.LoginAuthenticationExceptionHandler;
import nl._42.restsecure.autoconfigure.errorhandling.RestAccessDeniedHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Auto-configures Spring Web Security with a customized UserDetailsService for internal users storage or with crowd-integration-springsecurity for external crowd authentication.
 * Spring Method Security is enabled: You can make use of `@PreAuthorize` and `@PostAuthorize`.
 * Customizable authentication endpoints provided:
 * POST `/authentication` - to be able to login clients should provide a json request body like `{ username: 'user@email.com', password: 'secret'}`.
 * GET `/authentication/current` - to obtain the current logged in user
 */
@Configuration
@AutoConfigureAfter(WebMvcAutoConfiguration.class)
@ComponentScan(basePackageClasses = { AuthenticationController.class, GenericErrorHandler.class })
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityAutoConfig extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(WebSecurityAutoConfig.class);
    private final RestAccessDeniedHandler accessDeniedHandler;

    private AbstractRestAuthenticationSuccessHandler<? extends RegisteredUser> authenticationSuccessHandler;
    private AbstractUserDetailsService<? extends RegisteredUser> userDetailsService;
    private List<AuthenticationProvider> authProviders = new ArrayList<>();
    private RequestAuthorizationCustomizer authCustomizer;
    private HttpSecurityCustomizer httpCustomizer;
    private WebSecurityCustomizer webSecurityCustomizer;
    private RememberMeServices rememberMeServices;

    @Autowired(required = false)
    public void setAuthenticationSuccessHandler(
            AbstractRestAuthenticationSuccessHandler<? extends RegisteredUser> authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    @Autowired(required = false)
    public void setUserDetailsService(
            AbstractUserDetailsService<? extends RegisteredUser> userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Autowired(required = false)
    public void setAuthProviders(List<AuthenticationProvider> authProviders) {
        this.authProviders = authProviders;
    }

    @Autowired(required = false)
    public void setAuthCustomizer(RequestAuthorizationCustomizer authCustomizer) {
        this.authCustomizer = authCustomizer;
    }

    @Autowired(required = false)
    public void setHttpCustomizer(HttpSecurityCustomizer httpCustomizer) {
        this.httpCustomizer = httpCustomizer;
    }

    @Autowired(required = false)
    public void setWebSecurityCustomizer(WebSecurityCustomizer webSecurityCustomizer) {
        this.webSecurityCustomizer = webSecurityCustomizer;
    }

    @Autowired(required = false)
    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }

    public WebSecurityAutoConfig(RestAccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
    }

    /**
     * Adds a {@link BCryptPasswordEncoder} to the {@link ApplicationContext} if no {@link PasswordEncoder} bean is found already.
     * @return PasswordEncoder
     */
    @Bean
    @ConditionalOnBean(AbstractUserDetailsService.class)
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        log.info("Adding default BCryptPasswordEncoder to ApplicationContext.");
        return new BCryptPasswordEncoder();
    }

    /**
     * Adds an {@link UserProvider} to the {@link ApplicationContext} if no {@link UserProvider} bean is found already.
     * @return UserMapper
     */
    @Bean
    @ConditionalOnMissingBean(UserProvider.class)
    public UserProvider userProvider() {
        return new DefaultUserProvider();
    }

    @Bean
    @ConditionalOnMissingBean(LoginAuthenticationExceptionHandler.class)
    public LoginAuthenticationExceptionHandler loginExceptionHandler(GenericErrorHandler errorHandler) {
        return new DefaultLoginAuthenticationExceptionHandler(errorHandler);
    }

    /**
     * Adds an {@link AuthenticationResultProvider} to the {@link ApplicationContext} if no {@link AuthenticationResultProvider} bean is found already.
     * @return AuthenticationResultProvider
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationResultProvider.class)
    public AuthenticationResultProvider<? extends RegisteredUser> authenticationResultProvider() {
        return new DefaultAuthenticationResultProvider();
    }

    /**
     * {@inheritDoc}
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (userDetailsService != null) {
            log.info("Found UserDetailService in ApplicationContext.");
            auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        }
        if (!authProviders.isEmpty()) {
            log.info("Found AuthenticationProvider(s) in ApplicationContext.");
            authProviders.forEach(authProvider -> {
                log.info("\t Registering '{}' as authentication provider.", authProvider.getClass().getSimpleName());
                auth.authenticationProvider(authProvider);
            });
        }
        if (userDetailsService == null && authProviders.isEmpty()) {
            throw new IllegalStateException(
                "Cannot configure security; either a UserDetailsService or AuthenticationProvider bean must be present."
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        if (webSecurityCustomizer != null) {
            log.info("Found WebSecurityCustomizer bean in ApplicationContext, custom configuring of WebSecurity object started.");
            webSecurityCustomizer.configure(web);
        } else {
            log.info("No WebSecurityCustomizer bean found in ApplicationContext, no custom configuring of WebSecurity object.");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry = http
            .addFilterBefore(authenticationFilter(), AnonymousAuthenticationFilter.class)
            .authorizeRequests()
                .antMatchers("/authentication").permitAll();
        customize(urlRegistry)
            .anyRequest().fullyAuthenticated()
            .and()
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler)
                    .authenticationEntryPoint(accessDeniedHandler)
            .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/authentication", DELETE.name()))
                    .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
            .and()
                .csrf()
                    .csrfTokenRepository(csrfTokenRepository());
        customize(http);
    }
   
    private Filter authenticationFilter() throws Exception {
        RestAuthenticationFilter filter = new RestAuthenticationFilter(loginExceptionHandler(null), authenticationManagerBean());
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        filter.setRememberMeServices(rememberMeServices);
        return filter;
    }
    
    private ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry customize(
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry) {
        if (authCustomizer != null) {
            log.info("Found RequestAuthorization bean in ApplicationContext, custom configuring of urlRegistry object started.");
            return authCustomizer.customize(urlRegistry);
        } else {
            log.info("No RequestAuthorization bean found in ApplicationContext, no custom configuring of urlRegistry object.");
        }
        return urlRegistry;
    }

    private void customize(HttpSecurity http) throws Exception {
        if (httpCustomizer != null) {
            log.info("Found HttpSecurityCustomizer bean in ApplicationContext, custom configuring of HttpSecurity object started.");
            httpCustomizer.customize(http);
        } else {
            log.info("No HttpSecurityCustomizer bean found in ApplicationContext, no custom configuring of HttpSecurity object.");
        }
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = withHttpOnlyFalse();
        repository.setCookiePath("/");
        return repository;
    }
}
