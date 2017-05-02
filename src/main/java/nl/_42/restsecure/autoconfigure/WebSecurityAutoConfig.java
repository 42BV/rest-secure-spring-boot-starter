package nl._42.restsecure.autoconfigure;

import static java.util.Arrays.asList;
import static java.util.ResourceBundle.getBundle;
import static java.util.stream.Collectors.toSet;
import static nl._42.restsecure.autoconfigure.userdetails.UserDetailsAdapter.ROLE_PREFIX;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.core.context.SecurityContextHolder.MODE_INHERITABLETHREADLOCAL;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
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
import com.fasterxml.jackson.databind.ObjectMapper;

import nl._42.restsecure.autoconfigure.components.GenericErrorHandler;
import nl._42.restsecure.autoconfigure.userdetails.AbstractUserDetailsService;

@Configuration
@AutoConfigureAfter(WebMvcAutoConfiguration.class)
@ComponentScan(basePackageClasses = GenericErrorHandler.class)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityAutoConfig extends WebSecurityConfigurerAdapter {

    static {
        SecurityContextHolder.setStrategyName(MODE_INHERITABLETHREADLOCAL);
    }

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private GenericErrorHandler errorHandler;
    @Autowired(required = false)
    private AbstractUserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired(required = false)
    private RequestAuthorizationCustomizer authCustomizer;
    @Autowired(required = false)
    private HttpSecurityCustomizer httpCustomizer;
    @Autowired(required = false)
    private AuthenticationManagerBuilderCustomizer authBuilderCustomizer;
    
    @Autowired(required = false)
    private AuthenticationProvider crowdAuthenticationProvider;
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (userDetailsService != null) {
            auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);    
        } else if (crowdAuthenticationProvider != null) {
            auth.authenticationProvider(crowdAuthenticationProvider);
        } else {
            throw new IllegalStateException("Cannot configure security; either an AbstractUserDetailsService bean must be provided or Crowd must be on the classpath.");
        }
        if (authBuilderCustomizer != null) {
            authBuilderCustomizer.customize(auth);
        }
    }
    
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
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
                .anonymous()
                    .authorities(asList())
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
    
    private HttpSecurity customize(HttpSecurity http) {
        if (httpCustomizer != null) {
            return httpCustomizer.customize(http);
        }
        return http;
    }
    
    private RestAuthenticationFilter authenticationFilter() throws Exception {
        AntPathRequestMatcher matcher = new AntPathRequestMatcher("/authentication", POST.name());
        return new RestAuthenticationFilter(errorHandler, matcher, authenticationManagerBean(), objectMapper);
    }

    private RestAccessDeniedHandler accessDeniedHandler() {
        return new RestAccessDeniedHandler(errorHandler);
    }

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
    
    @ConditionalOnResource(resources = "applicationContext-CrowdClient.xml")
    @ImportResource("classpath:/applicationContext-CrowdClient.xml")
    @Configuration
    public static class CrowdBeans {
        
        @Autowired
        private HttpAuthenticator httpAuthenticator;
        @Autowired
        private GroupMembershipManager groupMembershipManager;
        @Autowired
        private CacheAwareAuthenticationManager crowdAuthenticationManager;
        @Autowired
        private UserManager userManager;
        
        @Bean
        public AuthenticationProvider crowdAuthenticationProvider() throws Exception {
            return new RemoteCrowdAuthenticationProvider(crowdAuthenticationManager, httpAuthenticator, crowdUserDetailsService());
        }
        
        private CrowdUserDetailsService crowdUserDetailsService() {
            CrowdUserDetailsServiceImpl crowdUserDetailsService = new CrowdUserDetailsServiceImpl();
            crowdUserDetailsService.setAuthenticationManager(crowdAuthenticationManager);
            crowdUserDetailsService.setGroupMembershipManager(groupMembershipManager);
            crowdUserDetailsService.setUserManager(userManager);
            Set<Entry<String, String>> roleMappings = loadCrowdGroupToRoleMappings();
            if (roleMappings != null) {
                crowdUserDetailsService.setGroupToAuthorityMappings(roleMappings);
            } else {
                crowdUserDetailsService.setAuthorityPrefix(ROLE_PREFIX);
            }
            return crowdUserDetailsService;
        }
        
        private Set<Entry<String, String>> loadCrowdGroupToRoleMappings() {
            try {
                ResourceBundle roleMappings = getBundle("crowd-group-to-role");
                return roleMappings.keySet().stream()
                    .map(key -> new SimpleEntry<String, String>(key, ROLE_PREFIX + roleMappings.getString(key)))
                    .collect(toSet());
            } catch (MissingResourceException mre) {
                return null;
            }
        }
    }
}
