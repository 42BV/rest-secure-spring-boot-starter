[![Build Status](https://github.com/42BV/rest-secure-spring-boot-starter/workflows/Java%20CI%20with%20Maven/badge.svg)](https://github.com/42BV/rest-secure-spring-boot-starter/actions?query=workflow%3A%22Java+CI+with+Maven%22)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/fc6f224a2c0e40a893521b320637ad3e)](https://www.codacy.com/gh/42BV/rest-secure-spring-boot-starter/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=42BV/rest-secure-spring-boot-starter&amp;utm_campaign=Badge_Grade)
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
    * DELETE `/authentication` - to logout the current logged in user
- Remember me support
- Support for two-factor authentication (2FA).
- CSRF protection by the [double submit cookie](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie)
  pattern. Implemented by using the [CsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.html#csrf-cookie).
- The @CurrentUser annotation may be used to annotate a controller method argument to inject the current custom user.
- Note the UserResolver spring bean that is added to your appication context, conveniently get the current logged in user from the SecurityContext!
- This autoconfiguration does not make assumptions of how you implement the "authorities" of a User. Spring Security can interpret your authorities by looking
  at a prefix; if you prefix an authority with "ROLE_", the framework provides a specific role-checking-api. But you can always use the more generic
  authority-checking-api.
    * For instance if you want to make use of "roles" and the Spring Security "hasRole(..)"-api methods, you must prefix your roles with the default "ROLE_".
    * If you want to avoid doing anything with prefixing, you are advised to make use of the more generic "hasAuthority(..)"-api methods.

## Setup for internal database users store (username and password authentication)

- You must have the following components in your application:
    * A database table where the users are stored.
    * A custom User domain class that maps on this database table using JPA.
    * A custom `UserRepository` that provides a method to obtain a custom User by the field that will be used as username using spring-data-jpa.

- The maven dependencies you need:

```xml

<dependencies>
    <dependency>
        <groupId>nl.42</groupId>
        <artifactId>rest-secure-spring-boot-starter</artifactId>
        <version>13.0.0</version>
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
</dependencies>
```

- Register a `UserDetailsService` or `AuthenticationProvider` and add it as a `Bean` to your Spring `ApplicationContext`:

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

We will also automatically detect and use all registered authentication providers. This way
we could even support multiple implementations at once, e.g. local database, CROWD and JWT. Spring will automatically attempt to authenticate
on all providers that support the authentication token:

```java

@Configuration
class CustomSecurity {
    @Bean
    public AuthenticationProvider crowdAuthenticationProvider() {
        return new CrowdAuthenticationProvider();
    }
}
```

- By default, a `BcryptPasswordEncoder` bean is added to the security config for password matching. Use this bean when you are encrypting passwords for your
  User domain object.
  If you want to override this bean, you can provide a custom `PasswordEncoder` implementation by adding it to your Spring `ApplicationContext`.

## Setup for multi-factor authentication (MFA, 2FA)

Rest-secure optionally supports multi-factor authentication using Time-based One-Time Password (TOTP).
This allows requiring users to enter a verification code to sign in (e.g. from Google Authenticator, Microsoft authenticator or similar apps)

To setup multi-factor authentication, follow the following steps:

### Setup internal database authentication

- Perform the steps **up to configuring a custom auth provider**
  in [Setup for internal database users store (username and password authentication)](#setup-for-internal-database-users-store-username-and-password-authentication)

### Configure the MFA authentication provider

- Configure the `MfaAuthenticationProvider` in your Spring `ApplicationContext`:

```java

@Configuration
class CustomSecurity {
    @Bean
    public MfaAuthenticationProvider mfaAuthenticationProvider(SpringUserDetailsService userDetailsService, PasswordEncoder passwordEncoder,
            MfaValidationService mfaValidationService) {
        MfaAuthenticationProvider authenticationProvider = new MfaAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        authenticationProvider.setMfaValidationService(mfaValidationService);
        return authenticationProvider;
    }
}
```

- In this example, the `SpringUserDetailsService` is the custom implementation of `UserDetailsService` which you've had to set up
  in [Setup internal database authentication](#setup-internal-database-authentication).
- `PasswordEncoder` and `MfaValidationService` are beans provided by `rest-secure-spring-boot-starter`

You'll need a custom User domain object (see [Using a custom User domain object](#using-a-custom-user-domain-object)). Make sure this object implements the
following methods:

- `isMfaConfigured()`: Indicates whether this user has successfully configured MFA. The user *must* have entered at least one valid verification code in order
  to configure MFA!
- `getMfaSecretKey()`: Contains the secret key to validate the MFA against. This key may *never* be exposed on endpoints!
- `isMfaMandatory()`: Indicates whether this user is obliged to use MFA. Can be a check based on user roles, or if MFA is always required simply return `true`

### If (some) users are mandatory to use MFA: Configure the filter for mandatory MFA authentication (IMPORTANT!)

If `isMfaMandatory()` is implemented (meaning it can return `true` in some case), you **must** define an implementation of the `MfaSetupRequiredFilter` in your
Spring `ApplicationContext` and add it to the filter chain using the `HttpSecurityCustomizer`:

```java

@Configuration
class CustomSecurity {
    @Bean
    public MfaSetupRequiredFilter mfaSetupRequiredFilter(ObjectMapper objectMapper) {
        MfaSetupRequiredFilter mfaSetupRequiredFilter = new MfaSetupRequiredFilter();

        // Add any excluded URLs to your filter if needed
        mfaSetupRequiredFilter.getExcludedRequests().add(new AntPathRequestMatcher("/enums/**", GET.name()));
        mfaSetupRequiredFilter.getExcludedRequests().add(new AntPathRequestMatcher("/mfa-setup/**", GET.name()));

        // Add any custom logic check exclusions to your filter if needed
        mfaSetupRequiredFilter.getExclusionChecks().add((req, res) -> SecurityContextHolder.getContext().getAuthentication() instanceof LoginAsAuthentication);

        mfaSetupRequiredFilter.setObjectMapper(objectMapper);

        return mfaSetupRequiredFilter;
    }

    @Bean
    public HttpSecurityCustomizer httpSecurityCustomizer() {
        return http -> http
                // Other config of your application may be located here. Keep that if it exists.
                .addFilterAfter(mfaSetupRequiredFilter(null), AnonymousAuthenticationFilter.class);
    }
}
```

⚠️ ⚠️
Forgetting to add this filter will **NOT** enforce the mandatory MFA authentication for users that meeds the criteria!!

### Add issuer name to the application config

Add the name of the application for display in the authenticator app to `application.yml`:

```yaml
totp:
  issuer: Your Application Name Goes Here
```

### Implementing the configuration and validation endpoints

Finally, your application needs to implement 3 endpoints to let users perform MFA configuration:

- Request MFA activation code (QR code) (should call `mfaSetupService.generateSecret()`, store the secret key and
  call `mfaSetupService.generateQrCode(secret, label)`).
    - The `label` will appear in the user's authenticator app and must be something like the user's username or email address.
- Configure MFA authentication (the user supplies a valid authentication code, verify it using `mfaValidationService.validateMfaCode(secret, code)` and
  set `isMfaConfigured` to true to confirm using MFA)
- Disable MFA authentication (optional), removes `mfaSecretKey` and `isMfaConfigured` for this User.

### Requirements of the configuration and validation endpoints

Below you'll find more detailed requirements of each endpoint:

#### Request activation code endpoint

- This endpoint may only be called when `isMfaConfigured` of this user returns `false`
- The output contains a base64-encoded PNG of the QR code (DATA URI). This can be used in HTML img elements to show the QR code
- This will assign the `mfaSecretKey` of this user.

#### Configure MFA authentication

- This endpoint may only be called when `isMfaConfigured` returns `false` and `getMfaSecretKey` of the User object returns a secret key
- The user **must** supply at least one valid authentication code (validate using `mfaValidationService.verifyMfaCode(secret, code)`)
- Calling this endpoint will set `isMfaConfigured` to `true` for this User.

#### Disable MFA authentication

- This endpoint may only be called when `isMfaConfigured` for this user returns `true`
- This endpoint may only be called when the user is signed in (and thus has entered a valid MFA code...)
    - Optionally, you can require the user to enter another MFA code when disabling MFA.

### Overriding any of the provided beans

- By default, a `BcryptPasswordEncoder` bean is added to the security config for password matching. Use this bean when you are encrypting passwords for your
  User domain object.
    - If you want to override this bean, you can provide a custom `PasswordEncoder` implementation by adding it to your Spring `ApplicationContext`.
- The `MfaValidationService` and `MfaSetupService` beans are automatically created by `rest-secure-spring-boot-starter`.
    - If you want to override these beans, you can provide a custom `MfaValidationService` or `MfaSetupService` implementation by adding it to your
      Spring `ApplicationContext`.

## Customization

### Using a custom User domain object

To use a custom User object we should implement the `RegisteredUser` interface (using the email field as username):

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

If your custom User domain object has custom properties for `accountExpired`, `accountLocked`, `credentialsExpired` or `enabled`,
you should override the corresponding default RegisteredUser methods. These methods are checked during a successful authentication, by
default they are all valid.

```java
public class User implements RegisteredUser {
    private boolean active;

    @Override
    public boolean isEnabled() {
        return active;
    }
}
```

Some utilities of this library (@CurrentUser, AuthenticationResultProvider, see below) make use of the principal that is available in the SecurityContext.
If making use of the local database users setup, the authentication principal will be of type `UserDetailsAdapter` wrapping our custom implementation
of the `RegisteredUser` interface. The utils will have access to a user object of our `RegisteredUser` implementation type automatically.

When adding an AuthenticationProvider with a UserDetailsService for other users storage (e.g. CROWD), we can register a `UserProvider` capable of converting
an `Authentication` into a `RegisteredUser` to ensure that the utilities are able to otain a user of correct type:

 ```java

@Service
public class UserService implements UserProvider {
    @Override
    public User toUser(Authentication authentication) {
        CrowdUserDetails userDetails = (CrowdUserDetails) authentication.getPrincipal();
        return userRepository.findByEmail(userDetails.getEmail());
    }
}
```

`RegisteredUser` instances can be injected into any controller method, using the `@CurrentUser` annotation:

```java

@RestController
@RequestMapping("/users")
public class UserController {
    @GetMapping("/me")
    public RegisteredUser current(@CurrentUser User user) {
        return user;
    }
}
```

And get returned by our global `/authentication` endpoints.

### Customizing the authentication endpoints

- The 2 authentication endpoints will return the following json by default:
    * POST /authentication and GET /authentication/current:

```
{
    username: 'peter@email.com', 
    authorities: ['ROLE_USER']
}
```

- The json returned for /authentication and /authentication/current can be customized by implementing the `AuthenticationResultProvider` and adding it
  as `Bean` to the Spring `ApplicationContext`:

```java

@Component
public class UserResultProvider implements AuthenticationResultProvider<User> {
    private final BeanMapper beanMapper;

    @Override
    public UserResult toResult(HttpServletRequest request, HttpServletResponse response, User user) {
        UserResult result = beanMapper.map(user, UserResult.class);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        result.restorable = authentication instanceof LoginAsAuthentication;
        result.fullyAuthenticated = authentication instanceof UsernamePasswordAuthenticationToken;
        return result;
    }
}
```

### Adding custom filters

- Use HttpSecurityCustomizer to add your custom filters to the `SpringSecurityFilterChain` and customize the `HttpSecurity` object in general:

```java

@Configuration
public class CustomSecurityConfig {
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
}
```

### Configuring request url authorization

- By default the authentication endpoints are configured accessible for any request, all other url's require full authentication. You may want to add url
  patterns in between these. Implement `RequestAuthorizationCustomizer` and add it as a `Bean` to the Spring `ApplicationContext`:

```java

@Configuration
class CustomSecurity {
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
}
```

### Using the `WebSecurityCustomizer`

```java

@Configuration
class CustomSecurity {
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return new WebSecurityCustomizer() {
            @Override
            public void configure(WebSecurity web) throws Exception {
                web.ignoring().antMatchers("/system/**");
            }
        };
    }
}
```

### Adding custom MFA verification checks (e.g. email, SMS)

The `MfaAuthenticationProvider` supports custom authentication checks in addition to the default TOTP validator.
If, for example, some portion of users receive their code through other means, it may be needed to add a custom verification check.

Note that the default TOTP check *always* gets added to the chain.
If it is not already supplied in the list of custom checks, it will be added after the last custom verification check.

A verification check should behave as following:

- If the user is successfully authenticated using the given verification code, return `true`. The user will be logged in and no other checks will be performed.
- If the check is not applicable to this user (e.g. this user does not receive codes using SMS), return `false`. The next check will then be executed.
- If the user has supplied incorrect credentials, the check must throw a subclass of `AuthenticationException` to abort the chain of checks and return a login
  error.

### Remember me (single sign on)

- Register a `RememberMeServices` bean, this will be picked up automatically and used in the login filter

```java

@Configuration
class CustomSecurity {
    @Bean
    public RememberMeServices rememberMeServices() {
        return new MyRememberMeServices();
    }
}
```

### Errorhandling

- For handling AuthenticationException's during login, a DefaultLoginAuthenticationExceptionHandler bean is created. AuthenticationExceptions during login will
  all result in a http response with status 401 with RFC-7807 json body and custom property:

```
{ errorCode: 'SERVER.LOGIN_FAILED_ERROR' }
```

If you want to handle these exceptions yourself, you can add a bean to the applicationContext that implements the `LoginAuthenticationExceptionHandler`
interface with bean name `loginExceptionHandler`.
You might want to inject the `GenericErrorHandler` bean in your implementation to help with writing your custom code to the response, e.g:

```java

@Component("loginExceptionHandler")
@RequiredArgsConstructor
public class CustomLoginExceptionHandler implements LoginAuthenticationExceptionHandler {

    private final GenericErrorHandler errorHandler;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        if (exception instanceof UsernameNotFoundException) {
            errorHandler.respond(response, HttpStatus.UNAUTHORIZED, "login.failed.username.not.found");
        } else {
            errorHandler.respond(response, HttpStatus.UNAUTHORIZED, "login.failed");
        }
    }
}
```

- An `@ExceptionHandler` method for handling the method security `AccessDeniedExcption` is added to a `@RestControllerAdvice` with `@Order(0)`. This way all
  custom `@ControllerAdvice` with `@ExceptionHandler` methods with default order will be processed hereafter. The http response will have a http status 403 with RFC-7807 json body and custom property:

```
{ errroCode: 'SERVER.ACCESS_DENIED_ERROR' }
```

If you want to handle this exception yourself, you can provide an `@ExceptionHandler` method within your custom `@ControllerAdvice` annotated with `@Order` with
a higher precedence (value less than zero!):

- Following error situations are not customizable:
    * Authentication errors when trying to access an url for which authentication is required:  
      Http status: 401  
      Response RFC-7807 json body and custom property: `{ errorCode: 'SERVER.AUTHENTICATE_ERROR' }`
    * Authorization errors when trying to access an url that needs a specific authority:  
      Http status: 403  
      Response RFC-7807 json body and custom property: `{ errorCode: 'SERVER.ACCESS_DENIED_ERROR' }`
    * Invalid session (e.g. timeout or after logout):  
      Http status: 401  
      Response RFC-7807 json body and custom property: `{ errorCode: 'SERVER.SESSION_INVALID_ERROR' }`

### Successful authentication handling

- If you want to add custom behaviour after each successful authentication, you can implement `AbstractRestAuthenticationSuccessHandler` and add it
  as bean to your application context.

## Multiple HttpSecurity configurations

If you want to add more to the HttpSecurity you can do this in two ways as shown below. This is not rest-secure specific and works in every project that uses
spring-security.

### Before 12.0.0

```java

@Configuration
@Order(1) // This is the important part
@RequiredArgsConstructor
public static class PublicEndpointsSecurityConfig extends WebSecurityConfigurerAdapter {

    private final WhitelistService whitelistService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/public/**")
                .authorizeRequests()
                .anyRequest().hasAnyRole("PUBLIC_API_ROLE");
        // more configuration
    }
}

@Configuration
@Order(2) // This is the important part
@RequiredArgsConstructor
public static class RegistrationNodeExternalApiSecurityConfig extends WebSecurityConfigurerAdapter {

    private final ExternalApiConfig externalApiConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/external-system/**")
                .authorizeRequests()
                .anyRequest().hasAnyRole("EXTERNAL_SYSTEM_ROLE");
        // more configuration
    }
}
```

### After 12.0.0

```java 

@Configuration
@RequiredArgsConstructor
public class CustomConfig {

    private final WhitelistService whitelistService;
    private final ExternalApiConfig externalApiConfig;

    @Bean
    @Order(1) // This is the important part
    public SecurityFilterChain publicApi(HttpSecurity http) throws Exception {
        http.antMatcher("/public/**")
                .authorizeRequests()
                .anyRequest().hasAnyRole("PUBLIC_API_ROLE");
        // more configuration
        return http.build();
    }

    @Bean
    @Order(2) // This is the important part
    public SecurityFilterChain registrationNodeExternalApi(HttpSecurity http) throws Exception {
        http.antMatcher("/external-system/**")
                .authorizeRequests()
                .anyRequest().hasAnyRole("EXTERNAL_SYSTEM_ROLE");
        // more configuration
        return http.build();
    }
}
```
