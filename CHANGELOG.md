# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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