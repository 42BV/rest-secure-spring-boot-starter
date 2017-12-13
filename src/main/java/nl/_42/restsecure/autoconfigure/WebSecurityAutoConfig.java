package nl._42.restsecure.autoconfigure;

import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.core.context.SecurityContextHolder.MODE_INHERITABLETHREADLOCAL;
import static org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse;
import static org.springframework.util.Assert.notEmpty;

import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import nl._42.restsecure.autoconfigure.components.AuthenticationController;
import nl._42.restsecure.autoconfigure.components.errorhandling.GenericErrorHandler;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.http.VerifyTokenFilter;
import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsService;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsServiceImpl;
import com.atlassian.crowd.service.GroupMembershipManager;
import com.atlassian.crowd.service.UserManager;
import com.atlassian.crowd.service.cache.CacheAwareAuthenticationManager;

/**
 * Auto-configures Spring Web Security with a customized UserDetailsService for internal users storage or with crowd-integration-springsecurity for external crowd authentication.
 * Spring Method Security is enabled: You can make use of `@PreAuthorize` and `@PostAuthorize`.
 * Customizable authentication endpoints provided:
 * POST `/authentication` - to be able to login clients should provide a json request body like `{ username: 'user@email.com', password: 'secret'}`.
 * GET `/authentication/handshake` - to obtain the current csrf token
 * GET `/authentication/current` - to obtain the current logged in user
 */
@Configuration
@AutoConfigureAfter(WebMvcAutoConfiguration.class)
@ComponentScan(basePackageClasses = AuthenticationController.class)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityAutoConfig extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(WebSecurityAutoConfig.class);

    static {
        SecurityContextHolder.setStrategyName(MODE_INHERITABLETHREADLOCAL);
    }

    @Autowired
    private GenericErrorHandler errorHandler;
    @Autowired(required = false)
    private AbstractUserDetailsService<? extends RegisteredUser> userDetailsService;

    @Autowired(required = false)
    private RequestAuthorizationCustomizer authCustomizer;
    @Autowired(required = false)
    private HttpSecurityCustomizer httpCustomizer;
    @Autowired(required = false)
    private CustomAuthenticationProviders customAuthenticationProviders;
    @Autowired(required = false)
    private WebSecurityCustomizer webSecurityCustomizer;

    @Autowired(required = false)
    private AuthenticationProvider crowdAuthenticationProvider;

    /**
     * {@inheritDoc}
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (userDetailsService != null) {
            log.info("Found userDetailService in ApplicationContext; configuring for local authentication store.");
            auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        } else if (crowdAuthenticationProvider != null) {
            log.info("Found crowd authenticationProvider in ApplicationContext; configuring for crowd authentication store.");
            auth.authenticationProvider(crowdAuthenticationProvider);
        } else {
            throw new IllegalStateException(
                    "Cannot configure security; either an AbstractUserDetailsService bean must be provided "
                            + "or crowd-integration-springsecurity.jar with crowd.properties must be on the classpath.");
        }
        if (customAuthenticationProviders != null) {
            List<AuthenticationProvider> providers = customAuthenticationProviders.get();
            notEmpty(providers, "CustomAuthenticationProviders bean must return at least one AuthenticationProvider.");
            log.info("Found customAuthenticationProviders bean in ApplicationContext; adding {} custom providers to web security.", providers.size());
            providers.forEach(auth::authenticationProvider);
        }
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
            .antMatchers("/authentication").permitAll()
            .antMatchers("/authentication/handshake").permitAll();
        customize(urlRegistry)
            .anyRequest().fullyAuthenticated()
            .and()
            .exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler())
            .authenticationEntryPoint(accessDeniedHandler())
            .and()
            .logout()
            .logoutRequestMatcher(new AntPathRequestMatcher("/authentication", DELETE.name()))
            .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
            .and().csrf().csrfTokenRepository(csrfTokenRepository());
        customize(http);
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

    private HttpSecurity customize(HttpSecurity http) throws Exception {
        if (httpCustomizer != null) {
            log.info("Found HttpSecurityCustomizer bean in ApplicationContext, custom configuring of HttpSecurity object started.");
            return httpCustomizer.customize(http);
        } else {
            log.info("No HttpSecurityCustomizer bean found in ApplicationContext, no custom configuring of HttpSecurity object.");
        }
        return http;
    }

    private RestAuthenticationFilter authenticationFilter() throws Exception {
        AntPathRequestMatcher matcher = new AntPathRequestMatcher("/authentication", POST.name());
        return new RestAuthenticationFilter(errorHandler, matcher, authenticationManagerBean());
    }

    private RestAccessDeniedHandler accessDeniedHandler() {
        return new RestAccessDeniedHandler(errorHandler);
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = withHttpOnlyFalse();
        repository.setCookiePath("/");
        return repository;
    }

    /**
     * Autoconfigures Crowd when a crowd-integration-springsecurity jar and a crowd.properties are found on the application's classpath.
     * When a crowd-group-to-role.properties is found on the application's classpath, these mappings will be used by the {@link CrowdUserDetailsService}
     */
    @ConditionalOnResource(resources = { "classpath:/applicationContext-CrowdClient.xml", "classpath:/crowd.properties" })
    @ImportResource("classpath:/applicationContext-CrowdClient.xml")
    @Configuration
    @EnableConfigurationProperties(RestSecureProperties.class)
    public static class CrowdBeans {

        private final Logger log = LoggerFactory.getLogger(CrowdBeans.class);

        @Autowired
        private HttpAuthenticator httpAuthenticator;
        @Autowired
        private GroupMembershipManager groupMembershipManager;
        @Autowired
        private CacheAwareAuthenticationManager crowdAuthenticationManager;
        @Autowired
        private UserManager userManager;
        @Autowired
        private RestSecureProperties props;

        @Bean
        public FilterRegistrationBean registration(VerifyTokenFilter filter) {
            FilterRegistrationBean registration = new FilterRegistrationBean(filter);
            registration.setEnabled(false);
            return registration;
        }

        @Bean
        public AuthenticationProvider crowdAuthenticationProvider() throws Exception {
            return new RemoteCrowdAuthenticationProvider(crowdAuthenticationManager, httpAuthenticator, crowdUserDetailsService());
        }

        @Bean
        public CrowdUserDetailsService crowdUserDetailsService() {
            CrowdUserDetailsServiceImpl crowdUserDetailsService = new CrowdUserDetailsServiceImpl();
            crowdUserDetailsService.setGroupMembershipManager(groupMembershipManager);
            crowdUserDetailsService.setUserManager(userManager);
            Set<Entry<String, String>> roleMappings = props.getCrowdGroupToAuthorityMappings();
            if (!roleMappings.isEmpty()) {
                log.info("Found rest-secure.authority-to-crowd-role-mappings in spring boot application properties.");
                roleMappings.forEach(roleMapping -> log.info("\t {}", roleMapping));
                crowdUserDetailsService.setGroupToAuthorityMappings(roleMappings);
            } else {
                log.warn(
                        "No rest-secure.authority-to-crowd-group-mappings in spring boot application properties found, no conversion of Crowd Groups will be applied!");
            }
            return crowdUserDetailsService;
        }
    }
}
