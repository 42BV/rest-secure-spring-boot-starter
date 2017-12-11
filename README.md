[![Build Status](https://travis-ci.org/42BV/rest-secure-spring-boot-starter.svg?branch=master)](https://travis-ci.org/42BV/rest-secure-spring-boot-starter)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/3f361d897c0c45afb6d0dae3dba16709)](https://www.codacy.com/app/sptdevos/rest-secure-spring-boot-starter?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=42BV/rest-secure-spring-boot-starter&amp;utm_campaign=Badge_Grade)
[![BCH compliance](https://bettercodehub.com/edge/badge/42BV/rest-secure-spring-boot-starter?branch=master)](https://bettercodehub.com/)
[![codecov](https://codecov.io/gh/42BV/rest-secure-spring-boot-starter/branch/master/graph/badge.svg)](https://codecov.io/gh/42BV/rest-secure-spring-boot-starter)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/nl.42/rest-secure-spring-boot-starter/badge.svg)](https://maven-badges.herokuapp.com/maven-central/nl.42/rest-secure-spring-boot-starter)
[![Javadoc](https://www.javadoc.io/badge/nl.42/rest-secure-spring-boot-starter.svg)](https://www.javadoc.io/doc/nl.42/rest-secure-spring-boot-starter)
[![Apache 2](http://img.shields.io/badge/license-Apache%202-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)

# rest-secure-spring-boot-starter

Spring boot autoconfig for spring security in a REST environment

## Features

- Auto-configures Spring Web Security with a customized UserDetailsService for internal database users storage or with crowd-integration-springsecurity for external crowd authentication.
- Spring Method Security is enabled: You can make use of `@PreAuthorize` and `@PostAuthorize`.
- Customizable authentication endpoints provided:
    * POST `/authentication` - to be able to login clients should provide a json request body like `{ username: 'user@email.com', password: 'secret'}`.
    * GET `/authentication/handshake` - to obtain the current csrf token
    * GET `/authentication/current` - to obtain the current logged in user
- The @CurrentUser annotation may be used to annotate a controller method argument to inject the current custom user.
- This autoconfiguration does not make assumptions of how you implement the "authorities" of a User. Spring Security can interpret your authorities by looking at a prefix; if you prefix an authority with "ROLE_", the framework provides a specific role-checking-api. But you can always use the more generic authority-checking-api.
    * For instance if you want to make use of "roles" and the Spring Security "hasRole(..)"-api methods, you must prefix your roles with the default "ROLE_".
    * If you want to avoid doing anything with prefixing, you are advised to make use of the more generic "hasAuthority(..)"-api methods.

## Setup for internal database users store

- You must have the following components in your application:
   * A database table where the users are stored.
   * A custom User domain class that maps on this database table using JPA.
   * A custom `UserRepository` that provides a method to obtain a custom User by the field that will be used as username using spring-data-jpa. 
   
- The maven dependencies you need:

```xml
<dependency>
    <groupId>nl.42</groupId>
    <artifactId>rest-secure-spring-boot-starter</artifactId>
    <version>2.0.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```
- Make your custom User domain object implement the `RegisteredUser` interface (using the email fields as username):
 
 ```java
@Entity
public class User implements RegisteredUser {
    @Id
    private Long id;
    private boolean active;
    private String email;
    private String password;
    private UserRole role;
    @Override
    public Set<String> getAuthorities() {
        Set<String> authorities = new HashSet<>();
        authorities.add("ROLE_" + role.name());
        return authorities;
    }
    @Override
    public String getUsername() {
        return email;
    }
    @Override
    public String getPassword() {
        return password;
    }
}
 ```
- Implement `AbstractUserDetailsService` and add it as a `Bean` to your Spring `ApplicationContext`:
 
```java
@Service
class SpringUserDetailsService extends AbstractUserDetailsService<User> {
    @Autowired
    private UserRepository userRepository;
    @Override
    protected User findUserByUsername(String username) {
        return userRepository.findByEmailIgnoreCase(username);
    }
}
```
- If your custom User domain object has custom properties for "accountExpired", "accountLocked", "credentialsExpired" or "userEnabled", 
you must override the corresponding default RegisteredUser methods:

```java
public class User implements RegisteredUser {
    private boolean active;
    @Override
    public boolean isEnabled() {
        return active;
    }
}
```
- By default, a `BcryptPasswordEncoder` bean is added to the security config for password matching. Use this bean when you are encrypting passwords for your User domain object.
If you want to override this bean, you can provide a custom `PasswordEncoder` implementation by adding it to your Spring `ApplicationContext`.

## Setup for crowd users store

- The maven dependencies you need:

```xml
<dependency>
    <groupId>nl.42</groupId>
    <artifactId>rest-secure-spring-boot-starter</artifactId>
    <version>2.0.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>com.atlassian.crowd</groupId>
    <artifactId>crowd-integration-springsecurity</artifactId>
    <version>1000.82.0</version>
    <exclusions>
        <exclusion>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
        </exclusion>
        <exclusion>
            <groupId>ognl</groupId>
            <artifactId>ognl</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```
- Provide your application with a `crowd-ehcache.xml` by adding it to the classpath. An example can be found in this project in directory: `src/test/resources/`.
- Provide your application with a `crowd.properties` by adding it to the classpath. For more information on this file see: [Atlassian documentation](https://confluence.atlassian.com/crowd/integrating-crowd-with-spring-security-174752019.html) chapter 2.3.
- If you want to map your custom application authorities to crowd-groups you can add these to your application.yml 
(Note that this only works for a 1 to 1 cardinality between authority and crowd-group):

 ```
 rest-secure:
   authority-to-crowd-group-mappings:
     ROLE_ADMIN: crowd-admin-group
     ROLE_USER: crowd-user-group 
 ```
- Put an implementation of `AbstractUserDetailsService<CrowdUser>` in your unittest configuration to be able to run spring boot webmvc tests:

```java
    @Profile("unit-test")
    @Configuration
    public class UnitTestAuthenticationStore {
        @Bean
        public PasswordEncoder passwordEncoder() {
            return NoOpPasswordEncoder.getInstance();
        }    
        @Bean
        public AbstractUserDetailsService<CrowdUser> userDetailsService() {
            return new AbstractUserDetailsService<CrowdUser>() {
                private Map<String, CrowdUser> users = new HashMap<>();
                @PostConstruct
                private void initUserStore() {
                    users.put("janAdmin", new CrowdUser("janAdmin", "secret", newHashSet("ROLE_" + ADMIN.name())));
                    users.put("janUser", new CrowdUser("janUser", "secret", newHashSet("ROLE_" + USER.name())));
                }
                @Override
                protected CrowdUser findUserByUsername(String username) {
                    return users.get(username);
                }
            };
        }
    }
```
## Customization

1. Adding custom filters:
- Use HttpSecurityCustomizer to add your custom filters to the `SpringSecurityFilterChain` and customize the `HttpSecurity` object in general:

```java
    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return new HttpSecurityCustomizer() {
            @Override
            public HttpSecurity customize(HttpSecurity http) throws Exception {
                http.addFilterBefore(rememberMeFilter(), AnonymousAuthenticationFilter.class)
                        .addFilterBefore(rememberMeAuthenticationFilter(), AnonymousAuthenticationFilter.class)
                        .addFilterAfter(httpLogFilter(), AnonymousAuthenticationFilter.class)
                        .logout()
                        .addLogoutHandler(rememberMeServices());
                return http;
            }
        };
    }
```
- Using the login request body json after the `RestAuthenticationFilter`:  
The restsecure autoconfig puts a `RestAuthenticationFilter` just before the Spring Security's `AnonymousAuthenticationFilter`.  
If you put a custom filter in between them (like the rememberMeFilter in the example above), you cannot read the request inputStream anymore when the request was a POST form login. This due to the fact that the `RestAuthenticationFilter` already has been reading the request inputStream to extract the usercredentials.  
To be able to access this information in subsequent filters, the `RestAuthenticationFilter` puts the request body as a request attribute after reading. You can retreive the request body like this:

```java
import static nl._42.restsecure.autoconfigure.RestAuthenticationFilter.LOGIN_FORM_JSON;

class RememberMeFilter extends OncePerRequestFilter {
    private final AntPathRequestMatcher matcher;
    private final ObjectMapper objectMapper;
    private final RememberMeServices rememberMeServices;
    RememberMeFilter(AntPathRequestMatcher matcher, ObjectMapper objectMapper, RememberMeServices rememberMeServices) {
        this.matcher = matcher;
        this.objectMapper = objectMapper;
        this.rememberMeServices = rememberMeServices;
    }
    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (matcher.matches(request)) {
            LoginForm form = objectMapper.readValue((String)request.getAttribute(LOGIN_FORM_JSON), LoginForm.class);
            if (form.rememberMe) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                rememberMeServices.loginSuccess(request, response, authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
```
- Note that the `RestAuthenticationFilter` must be able to read form the inputStream when the request is a POST login. So make sure you do not add filters before this one that read the request inputStream or no login credentials can be read to be able to authenticate!
 
2. Configuring request url authorization:
- By default the authentication endpoints are configured accessible for any request, all other url's require full authentication. You may want to add url patterns in between these. Implement `RequestAuthorizationCustomizer` and add it as a `Bean` to the Spring `ApplicationContext`:

```java
@Bean
public RequestAuthorizationCustomizer requestAuthorizationCustomizer() {
    return new RequestAuthorizationCustomizer() {
        @Override
        public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry customize(
                ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry) {
            return urlRegistry
                .antMatchers(GET, "/authentication/current").not().anonymous()
                .antMatchers(GET, "/constraints").not().anonymous()
                .antMatchers(GET, "/enums").not().anonymous()
                .antMatchers(GET, "/participations").not().anonymous();
        }
    };
}
```

3. Customizing the authentication endpoints:
- The 3 default authentication endpoints will return the following json by default:
   * POST /authentication and GET /authentication/current:
   
```
{
    username: 'peter@email.com', 
    authorities: ['ROLE_USER']
}
```
   * GET /authentication/handshake
   
```
{
    csrfToken: 'KbyUmhTLMpYj7CD2di7JKP1P3qmLlkPt'
}
```
- The json returned for /authentication and /authentication/current can be customized by implementing the `AuthenticationResultProvider<T>` and adding it as `Bean` to the Spring `ApplicationContext`.
Note on example below: `CustomAuthenticationResult` implements `AuthenticationResult`.

```java
@Component
public class CustomAuthenticationResultProvider implements AuthenticationResultProvider<User> {
    @Autowired
    private BeanMapper beanMapper;
    @Override
    public AuthenticationResult toAuthenticationResult(User user) {
        CustomAuthenticationResult result = beanMapper.map(user, CustomAuthenticationResult.class);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        result.restorable = authentication instanceof LoginAsAuthentication;
        result.fullyAuthenticated = authentication instanceof UsernamePasswordAuthenticationToken;
        return result;
    }
}
```
- When using Crowd as Authentication method, the user argument will always be of type `CrowdUser`:

```java
@Component
public class CustomAuthenticationResultProvider implements AuthenticationResultProvider<CrowdUser> {
    @Autowired
    private BeanMapper beanMapper;
    @Override
    public AuthenticationResult toAuthenticationResult(CrowdUser crowdUser) {
        return beanMapper.map(crowdUser, CustomAuthenticationResult.class); 
    }
}
```

4. Adding custom `AuthenticationProvider`'s:
- If you want to add an extra `AutenticationProvider` to the security config, implement the `CustomAuthenticationProviders` interface and add it as `Bean` to the Spring `ApplicationContext`:

```java
@Bean
public CustomAuthenticationProviders customAuthenticationProviders() {
    return new CustomAuthenticationProviders() {
        @Override
        public List<AuthenticationProvider> get() {
            return asList(rememberMeAuthenticationProvider());
        }
    };
}
```

5. Using the `WebSecurityCustomizer`:

```java
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return new WebSecurityCustomizer() {
        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring().antMatchers("/system/**");
        }            
    };
}
```

6. Errorhandling:
- An `@ExceptionHandler` method for handling the method security `AccessDeniedExcption` is added to a `@RestControllerAdvice` with `@Order(0)`. This way all custom `@ControllerAdvice` with `@ExceptionHandler` methods with default order will be processed hereafter. The http response will have a http status 403 with a json body:

```
{ errroCode: 'SERVER.ACCESS_DENIED_ERROR'}
```
If you want to handle this exception yourself, you can provide an `@ExceptionHandler` method within your custom `@ControllerAdvice` annotated with `@Order` with a higher precedence (value less that zero!):
- Following error situations are not (yet) customizable:
   * Authentication errors during login and authentication errors when trying to access a restricted url:  
Http status: 401  
Response body: `{ errorCode: 'SERVER.AUTHENTICATE_ERROR'}`
   * Authorization errors when trying to access a url that needs a specific authority:  
Http status: 403  
Response body: `{ errorCode: 'SERVER.ACCESS_DENIED_ERROR'}`
   * Csrf token missing due to session timeout:  
Http status: 401  
Response body: `{ errorCode: 'SERVER.SESSION_TIMEOUT_ERROR'}`

