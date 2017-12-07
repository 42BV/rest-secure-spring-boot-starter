# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2017-12-07

### Changed
- The custom XsrfHeaderFilter is removed in favor of the Spring Security CookieCsrfTokenRepository.
- Added tests for the `/authentication` endpoints. 

## [2.1.0] - 2017-11-29

### Changed
- Crowd usage changes:
    - Issue [#1](https://github.com/42BV/rest-secure-spring-boot-starter/issues/1): Removed crowd-ehcache.xml from jar. Now users have to provide this file.
    - Issue [#2](https://github.com/42BV/rest-secure-spring-boot-starter/issues/2): Now authorities are mapped to crowd-groups instead of the other way around.