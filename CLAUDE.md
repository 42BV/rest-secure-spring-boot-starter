# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A Spring Boot auto-configuration starter (published to Maven Central as `nl.42:rest-secure-spring-boot-starter`) that configures Spring Security for stateless-JSON REST APIs: JSON login/logout/current-user endpoints, CSRF via double-submit cookie, method security, remember-me, and optional TOTP-based MFA. Requires Java 21; built against Spring Boot 4.x.

## Commands

```bash
./mvnw test                                        # run all tests
./mvnw test -Dtest=WebSecurityAutoConfigTest       # run a single test class
./mvnw test -Dtest=WebSecurityAutoConfigTest#methodName  # run a single test method
./mvnw verify                                      # full build incl. JaCoCo report
./mvnw org.owasp:dependency-check-maven:check      # OWASP CVE scan (fails on any CVSS >= 1; suppressions in owasp-suppressions.xml)
```

Releases are done via the GitHub Action "Publish package to the Maven Central Repository" (see `sonatype-release-doc.md`), then published manually at central.sonatype.com. Keep `CHANGELOG.md` (Keep a Changelog format, semver) updated under `[Unreleased]` when making user-facing changes.

## Architecture

All code lives under `nl._42.restsecure.autoconfigure`. Two auto-configurations are registered in `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`:

- **`WebSecurityAutoConfig`** — the core. Builds the `SecurityFilterChain`: permits `/authentication` and `/authentication/current`, requires full authentication for everything else, wires the `RestAuthenticationFilter` (JSON body login via `RestAuthenticationFilterConfigurer`), CSRF cookie repository, session policy `ALWAYS`, and logout on `DELETE /authentication`. It builds the `AuthenticationManager` from either a user-supplied `AbstractUserDetailsService` bean or any `AuthenticationProvider` beans found in the context (at least one is mandatory — throws otherwise). Note: when an `MfaAuthenticationProvider` is present, the `UserDetailsService` is deliberately NOT registered directly, because the resulting `DaoAuthenticationProvider` would bypass MFA.
- **`MfaSecurityAutoConfig`** — optional TOTP-based MFA; only active when `dev.samstevens.totp` is on the classpath (the dependency is `<optional>` in the pom). MFA classes live in `authentication/mfa/`.

Consumer extension points are all opt-in beans discovered from the application context (mostly `@Autowired(required = false)` or `@ConditionalOnMissingBean`): `RequestAuthorizationCustomizer` (URL authorization rules), `HttpSecurityCustomizer` (arbitrary HttpSecurity changes, custom filters), `WebSecurityCustomizer`, `AuthenticationResultProvider` (shape of the authentication JSON), `LoginAuthenticationExceptionHandler` (bean name `loginExceptionHandler`), `AbstractRestAuthenticationSuccessHandler`, `RememberMeServices`, `PasswordEncoder` (defaults to BCrypt), `UserProvider`. The README documents each with examples — keep it in sync when changing extension points.

Key domain concepts in `authentication/`:
- `RegisteredUser` — the interface consumers implement on their user domain object; wrapped in `UserDetailsAdapter` to bridge to Spring Security's `UserDetails`.
- `AuthenticationController` — serves `POST /authentication`, `GET /authentication/current` (returns 200 with `authenticated: false` for anonymous callers, never 401), `DELETE /authentication`.
- `@CurrentUser` + `CurrentUserArgumentResolver` / `UserResolver` — inject the current user into controller methods or services.
- `errorhandling/` — RFC-7807 responses with an `errorCode` property (`SERVER.LOGIN_FAILED_ERROR`, `SERVER.ACCESS_DENIED_ERROR`, `SERVER.AUTHENTICATE_ERROR`, `SERVER.SESSION_TIMEOUT_ERROR`). Note: the constant `SERVER_SESSION_INVALID_ERROR` holds the value `SERVER.SESSION_TIMEOUT_ERROR`.

## Tests

Tests extend `AbstractApplicationContextTest`, which boots an `AnnotationConfigWebApplicationContext` with the auto-configs plus a scenario-specific `@Configuration` class and returns a security-aware `MockMvc`. Reusable scenario configs (active user, locked account, MFA variants, custom providers, etc.) live in `src/test/java/.../autoconfigure/test/` — add new scenarios there rather than inlining config in test classes.
