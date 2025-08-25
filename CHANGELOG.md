# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [14.1.0] - 2025-08-25
- FormUtil: Do not throw for invalid request body
  - When a HTTP request with an invalid request body (XML, HTML) is sent through either `RestAuthenticationFilter` or `RestAccessDeniedHandler`, FormUtil would fail with an `IllegalStateException`.
  - This often happens by automated / bot requests, thus should not lead to an exception.
  - Instead of throwing an exception, FormUtil now logs a warning and returns an empty form.

## [14.0.0] - 2025-07-23

- Removed `@Lazy` annotations from UserResolver references
  - To improve compatibility with Spring Native, various `@Lazy` annotations were removed, as they would interfere with Spring Native's proxy detection.
- Added constructor with `UserDetailsService` to `MFAProvider`
  - Added constructor in `MfaAuthenticationProvider` to pass the `userDetailsService` to its super class, because calling `setUserDetailsService` has been deprecated by Spring.
  - Fixed broken test setup in `RestAuthenticationSuccessHandlerConfig`
- Added GitHub Actions workflow for publishing to Maven Central
  - Adds the `release-action`, which can be manually started to publish a new version to Maven Central.


## [13.2.1]
- FIX: Removed unnecessary warn logs that are part of the login flow

## [13.2.0]
- Session fixation protection fixed 
- Added session creation policy `ALWAYS` to default configuration
- RestAuthenticationFilter now has a specific Customizer to be able to make use of shared objects within the HttpSecurity config

## [13.1.0]
- The `totp-spring-boot-starter` dependency is now optional
- If using the MFA functionality, add the dependency to your project

## [13.0.1] - 2024-09-25
- Codacy finding fixed

## [13.0.0] - 2024-09-24
- Upgrade to Spring Boot 3.3.4
- Moved to Java 21
- Internal code maintainability fixes

## [12.3.0] - 2023-12-07
- Upgrade to Spring Boot 3.2.0
- Made the AuthenticationManager in the WebSecurityAutoConfig conditional.
  - This gives the option to implement your own version of the AuthenticationManager.

## [12.2.0] - 2023-11-08
- Upgrade to Spring Boot 3.1.5
- Error response in RFC-7807 format
- Added maven wrapper

## [12.0.0] - 2023-02-23
- Upgrade to Spring Boot 3.0.2
- Upgrade to JDK 17

## [11.0.0] - 2021-12-23
- Upgrade: from spring-boot 2.5 to 2.6
- Now throwing an Exception in the RequestAuthorizationCustomizer's customize method so that
  you don't have to wrap exceptions in RuntimeExceptions if they are thrown in the implementing
  methods.

## [10.0.1] - 2021-12-20
- Added: additional constructor with customisable request matcher and ObjectMapper.

## [10.0.0] - 2021-12-17
- Added: Support for custom MFA checks, e.g. to also accept codes from email and SMS.

## [9.0.1] - 2021-11-18
- Fixed: #20 The label of the 2FA QR code should get the issuer added as well to work properly with all authenticator apps.

## [9.0.0] - 2021-11-17
- Added: Support for two-factor authentication (2FA, MFA)
- Upgrade: From spring-boot 2.4 to 2.5

## [8.0.2] - 2021-01-20
- Fix: Inconsistent constructor declaration on bean with name 'nl._42.restsecure.autoconfigure.WebSecurityAutoConfig'

## [8.0.1] - 2020-11-23
- Fix: circular dependency issue fixed for UserResolver in WebSecurityMvcAutoConfig

## [8.0.0] - 2020-11-19
- Upgrade: From java 8 to java 11
- Upgrade: From spring-boot 2.2 to 2.4
- Upgrade: From junit 4 to 5
- Upgrade: Pom no longer extends from sonatype pom which is deprecated
- Changed: UserResolver bean is now typed and no longer needs Authentication as argument,
also returns an Optional instead of a possible null value
- Added: Extension point for handling AuthenticationExceptions during login
- Fixed: Documentation fixes in readme.md

## [7.2.0] - 2019-12-16
- Removed `/authentication/handshake` http security configuration and documentation because it was removed a few versions ago already (since 3.0.0).
- Added the possibility to implement an `AbstractRestAuthenticationSuccessHandler` to customize behaviour after successful authentication.

## [7.1.0] - 2019-12-05
- Now it's possible to configure an AbstractUserDetailsService next to other AuthenticationProvider(s). 

## [7.0.1] - 2019-05-29
- Fixed circular dependency

## [7.0.0] - 2019-05-29
- REST authentication filter now supports `RememberMeServices`
- Removed CROWD, separating library from any Authentication Provider implementation
 * For CROWD we suggest using the `spring-boot-starter-crowd`

## [6.0.0] - 2019-05-07
- Now using REST to connect crowd server.

## [5.0.0] - 2019-02-20

### Changed
- Crowd client properties are now loaded from application.yml instead of a separate crowd.properties file on the classpath.

## [4.0.0] - 2018-12-20

### Changed
- Upgraded dependencies to be able to run on java 11

## [3.0.0] - 2018-02-12

### Removed
- The /authentication/handshake endpoint is no longer needed because of the 'double submit cookie'.

## [2.3.0] - 2017-12-14

### Fixed
- The `RestAccessDeniedHandler` no longer checks for a `CsrfTokenNotFoundException` to tell that the session is invalid. This because of no longer using the 'Synchronizer Token Pattern' for CSRF protection. Now the request's validity is checked upon a `AuthenticationException`.
- Code style violations fixed.
- Added tests to gain 100% coverage.

### Changed
- Package restructuring.

## [2.2.0] - 2017-12-07

### Changed
- The custom XsrfHeaderFilter is removed in favor of the Spring Security CookieCsrfTokenRepository.
   - 'Double Cookie Submit pattern' now used instead of 'Synchronizer Token Pattern'.
- Added tests for the `/authentication` endpoints. 

## [2.1.0] - 2017-11-29

### Changed
- Crowd usage changes:
    - Issue [#1](https://github.com/42BV/rest-secure-spring-boot-starter/issues/1): Removed crowd-ehcache.xml from jar. Now users have to provide this file.
    - Issue [#2](https://github.com/42BV/rest-secure-spring-boot-starter/issues/2): Now authorities are mapped to crowd-groups instead of the other way around.
