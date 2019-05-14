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

- Auto-configures Spring Web Security with a customized UserDetailsService for internal database users storage or any other authentication provider.
- Spring Method Security is enabled: You can make use of `@PreAuthorize` and `@PostAuthorize`.
- Customizable authentication endpoints provided:
    * POST `/authentication` - to be able to login clients should provide a json request body like `{ username: 'user@email.com', password: 'secret'}`.
    * GET `/authentication/current` - to obtain the current logged in user
- Remember me support
- CSRF protection by the [double submit cookie](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie) pattern. Implemented by using the [CsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.html#csrf-cookie).
- The @CurrentUser annotation may be used to annotate a controller method argument to inject the current custom user.
- This auto configuration does not make assumptions of how you implement the "authorities" of a User. Spring Security can interpret your authorities by looking at a prefix; if you prefix an authority with "ROLE_", the framework provides a specific role-checking-api. But you can always use the more generic authority-checking-api.
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
    <artifactId>spring-boot-starter-security-rest</artifactId>
    <version>6.1.0</version>
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

## Customization

1. Adding custom authentication providers:
- If you want to support another provider implementation, e.g. CROWD, register an `AutenticationProvider` or `AbstractUserDetailService` as `@Bean`.
This implementation will be picked up automatically and used during authentication:

```java
@Bean
public AuthenticationProvider crowdAuthenticationProvider() {
    return new ...;
}
```

2. Adding custom filters:
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
                    .logout().addLogoutHandler(rememberMeServices());
                return http;
            }
        };
    }
```
 
3. Configuring request url authorization:
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

4. Customizing the authentication endpoints:
- The 2 authentication endpoints will return the following json by default:
   * POST /authentication and GET /authentication/current:
   
```
{
    username: 'peter@email.com', 
    authorities: ['ROLE_USER']
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

6. Remember me (single sign on):
- Register a `RememberMeServices` bean, this will be picked up automatically and used in the login filter

```java
@Bean
public RememberMeServices rememberMeServices() {
    return new MyRememberMeServices();
}
```

7. Errorhandling:
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
   * Invalid session (e.g. timeout or after logout):  
Http status: 401  
Response body: `{ errorCode: 'SERVER.SESSION_INVALID_ERROR'}`
