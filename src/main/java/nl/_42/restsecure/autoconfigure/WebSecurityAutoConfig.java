package nl._42.restsecure.autoconfigure;

import static java.util.stream.Collectors.toList;
import static nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter.ROLE_PREFIX;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.core.context.SecurityContextHolder.MODE_INHERITABLETHREADLOCAL;

import java.io.IOException;
import java.util.Properties;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.springsecurity.RemoteCrowdAuthenticationProvider;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsService;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetailsServiceImpl;
import com.atlassian.crowd.service.GroupMembershipManager;
import com.atlassian.crowd.service.UserManager;
import com.atlassian.crowd.service.cache.CacheAwareAuthenticationManager;

import nl._42.restsecure.autoconfigure.components.AuthenticationController;
import nl._42.restsecure.autoconfigure.components.errorhandling.GenericErrorHandler;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;
import nl._42.restsecure.autoconfigure.userdetails.RegisteredUser;

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
    private InMemoryUsersStore inMemoryUsersStore;
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
        if (inMemoryUsersStore == null) {
            if (userDetailsService != null) {
                auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
            }
            if (crowdAuthenticationProvider != null) {
                auth.authenticationProvider(crowdAuthenticationProvider);
            }
            if (customAuthenticationProviders != null) {
                customAuthenticationProviders.get().forEach(auth::authenticationProvider);
            }
            if (userDetailsService == null && crowdAuthenticationProvider == null && customAuthenticationProviders == null) {
                throw new IllegalStateException("Cannot configure security; either an AbstractUserDetailsService- or CustomAuthenticationProviders bean must be provided "
                        + "or crowd-integration-springsecurity.jar with crowd.properties must be on the classpath.");
            }
        } else {
            log.warn("Now loading users with plaintext passwords in memory to build an authentication store, DO NOT USE THIS IN A PRODUCTION ENVIRONMENT!");
            InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> configurer = auth.inMemoryAuthentication();
            inMemoryUsersStore.users().forEach(user -> {
                configurer.withUser(user.getUsername())
                    .password(user.getPassword())
                    .authorities(user.getRolesAsString()
                            .stream()
                            .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                            .collect(toList()));
            });
        }
    }
    
    /**
     * Adds a {@link BCryptPasswordEncoder} to the {@link ApplicationContext} if no {@link PasswordEncoder} bean is found already.
     * @return PasswordEncoder
     */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
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
            webSecurityCustomizer.configure(web);
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
            .and()
                .csrf()
                    .csrfTokenRepository(csrfTokenRepository())
            .and()
                .addFilterAfter(new XsrfHeaderFilter(), CsrfFilter.class);
        customize(http);
    }

    private ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry customize(
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry) {
        if (authCustomizer != null) {
            return authCustomizer.customize(urlRegistry);
        }
        return urlRegistry;
    }
    
    private HttpSecurity customize(HttpSecurity http) throws Exception {
        if (httpCustomizer != null) {
            return httpCustomizer.customize(http);
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
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
    
    /**
     * Autoconfigures Crowd when a crowd-integration-springsecurity jar and a crowd.properties are found on the application's classpath.
     * When a crowd-group-to-role.properties is found on the application's classpath, these mappings will be used by the {@link CrowdUserDetailsService}
     */
    @ConditionalOnResource(resources = {"applicationContext-CrowdClient.xml", "crowd.properties"})
    @ImportResource("classpath:/applicationContext-CrowdClient.xml")
    @Configuration
    public static class CrowdBeans implements ResourceLoaderAware {
        
        @Autowired
        private HttpAuthenticator httpAuthenticator;
        @Autowired
        private GroupMembershipManager groupMembershipManager;
        @Autowired
        private CacheAwareAuthenticationManager crowdAuthenticationManager;
        @Autowired
        private UserManager userManager;
        private ResourceLoader resourceLoader;
        
        @Bean
        public AuthenticationProvider crowdAuthenticationProvider() throws Exception {
            return new RemoteCrowdAuthenticationProvider(crowdAuthenticationManager, httpAuthenticator, crowdUserDetailsService());
        }
        
        private CrowdUserDetailsService crowdUserDetailsService() {
            CrowdUserDetailsServiceImpl crowdUserDetailsService = new CrowdUserDetailsServiceImpl();
            crowdUserDetailsService.setAuthenticationManager(crowdAuthenticationManager);
            crowdUserDetailsService.setGroupMembershipManager(groupMembershipManager);
            crowdUserDetailsService.setUserManager(userManager);
            Set roleMappings = loadCrowdGroupToRoleMappings();
            if (roleMappings != null) {
                crowdUserDetailsService.setGroupToAuthorityMappings(roleMappings);
            } else {
                crowdUserDetailsService.setAuthorityPrefix(ROLE_PREFIX);
            }
            return crowdUserDetailsService;
        }
        
        private Set loadCrowdGroupToRoleMappings() {
            try {
                Properties roleMappings = new Properties();
                roleMappings.load(resourceLoader.getResource("classpath:crowd-group-to-role.properties").getInputStream());
                roleMappings.replaceAll((k, v) -> ROLE_PREFIX + v);
                return roleMappings.entrySet();
            } catch (IOException ioe) {
                return null;
            }
        }

        @Override
        public void setResourceLoader(ResourceLoader resourceLoader) {
            this.resourceLoader = resourceLoader;
        }
    }
}
