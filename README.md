# rest-secure-spring-boot-starter

Spring boot autoconfig for spring security in a REST environment

## Features

Auto-configures Spring Security with a customized UserDetailsService for internal users storage or with crowd-integration-springsecurity for external crowd authentication.

## Usage

1. The maven dependency you need:

```xml
<dependency>
    <groupId>nl.42</groupId>
    <artifactId>rest-secure-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```
2a. If you want to configure for an internal users storage:
 - Make your custom User domain object implement the `RegisteredUser` interface:
 ```java
@Entity
public class User extends BaseEntity implements RegisteredUser {
    private boolean active;
    private String email;
    private String password;
    private UserRole role;
    @Override
    public List<String> getRolesAsString() {
        return Arrays.asList(role.name());
    }
    @Override
    public String getUsername() {
        return email;ˇ
    }
}
 ```
 - Implement `AbstractUserDetailsService` and add it as a `Bean` to your Spring `ApplicationContext`:
```java
@Service
class SpringUserDetailsService extends AbstractUserDetailsService<User> {
    @Autowired
    private final UserRepository userRepository;ß
    @Override
    protected User findUserByUsername(String username) {
        return userRepository.findByEmailIgnoreCase(username);
    }
}
```
 - If your custom User domain object has properties for "accountExpired", "accountLocked", "credentialsExpired" or "userEnabled", 
you must implement the corresponding resolver and add it as a `Bean` to your Spring `ApplicationContext`:
```java
@Component
public class UserEnabledResolverImpl implements UserEnabledResolver<User> {
    @Override
    public boolean isEnabled(User user) {
        return user.isActive();
    }
}
```
 - By default, a `BcryptPasswordEncoder` bean is added to the security config for password matching. Use this bean when you are encrypting passwords for your User domain object.
If you want to override this bean, you can provide a custom `PasswordEncoder` implementation by adding it to your Spring `ApplicationContext`.

2b. If you want to configure for an external crowd authentication:
 - Add the crowd-integration-springsecurity dependency to your pom.xml:
```xml
<dependency>
    <groupId>com.atlassian.crowd</groupId>
    <artifactId>crowd-integration-springsecurity</artifactId>
    <version>2.7.2</version>
</dependency>
```
 - Provide your application with a `crowd.properties` by adding it to the classpath. For more information on this file see: https://confluence.atlassian.com/crowd/integrating-crowd-with-spring-security-174752019.html chapter 2.3
 - If you want to map crowd groups to your custom application user roles you can provide your application with a `crowd-group-to-role.properties` by adding it to the classpath:
 ```
 crowd-admin-group = ADMIN
 ```
  
## Customization

1. Adding custom filters:
- Use HttpSecurityCustomizer
- Using the login-form json after the `RestAuthenticationFilter`

2. Using the in-memory users store for testing purposes:

3. Configuring request url authorization:

4. Customizing the authentication endpoints:

5. Adding custom `AuthenticationProvider`'s:

6. Using the `WebSecurityCustomizer`:
