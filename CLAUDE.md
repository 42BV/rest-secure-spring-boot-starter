# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## BUILD COMMANDS
- Build project: `./mvnw clean install`
- Package: `./mvnw package`
- Skip tests: `./mvnw install -DskipTests`

## TEST COMMANDS
- Run all tests: `./mvnw test`
- Run single test: `./mvnw test -Dtest=TestClassName`
- Run specific method: `./mvnw test -Dtest=TestClassName#testMethodName`
- Security check: `./mvnw org.owasp:dependency-check-maven:check`

## CODE STYLE
- Java 21 syntax and features
- 4-space indentation
- Standard Java naming: camelCase for methods/variables, PascalCase for classes
- Lombok for reducing boilerplate
- Imports: Java standard libraries first, then third-party
- Error handling: Custom exceptions with RFC-7807 problem details
- Logging: Use LogUtil for exception logging
- HTTP status: 401 for authentication, 403 for authorization errors