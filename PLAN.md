# Email-based Multi-Factor Authentication Implementation Plan

This document outlines a comprehensive plan for adding Email-based Multi-Factor Authentication (MFA) to the rest-secure-spring-boot-starter library as an alternative to the existing TOTP-based MFA.

## 1. Analysis

### Current MFA Architecture
The current MFA implementation in the library is based on Time-based One-Time Password (TOTP) and follows these key patterns:

- **Verification Strategy Pattern**: Uses the `MfaVerificationCheck` interface to define MFA verification strategies
- **Clear Extension Points**: The `MfaAuthenticationProvider` supports multiple verification checks executed in sequence
- **Provider Configuration**: Using Spring Boot's auto-configuration to set up MFA components
- **User Interface**: The `RegisteredUser` interface defines MFA-related methods that applications must implement
- **Filter Mechanism**: Uses `MfaSetupRequiredFilter` to block access when MFA is required but not configured

### Key Extension Points
- The `MfaVerificationCheck` interface allows adding new verification methods
- The `RegisteredUser` interface can be extended with email MFA methods
- Auto-configuration can be enhanced to include email MFA components

## 2. Design

### Component Overview
We'll add the following new components:

1. **EmailCodeService**: Service for generating and validating email verification codes
2. **EmailCodeRepository**: Interface for storing and retrieving email verification codes
3. **MfaEmailVerificationCheck**: Implementation of `MfaVerificationCheck` for email verification
4. **EmailMfaProperties**: Configuration properties for email MFA

### User Flow
1. User logs in with username and password
2. If Email MFA is enabled, a verification code is sent via email
3. User receives the email and enters the code
4. System validates the code and completes authentication

### Data Model Enhancements
The `RegisteredUser` interface will be extended with:
- Method to determine the user's MFA method (TOTP, EMAIL, NONE)
- Method to get notification email address for MFA

## 3. Implementation

### Phase 1: Core Email MFA Service

1. Add new dependencies:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
    <optional>true</optional>
</dependency>
```

2. Create configuration properties:
```java
@ConfigurationProperties(prefix = "rest-secure.mfa.email")
public class EmailMfaProperties {
    private boolean enabled = false;
    private int codeLength = 6;
    private int codeValiditySeconds = 300;
    private String emailSubject = "Your verification code";
    private String emailFrom;
    // Getters and setters
}
```

3. Create email verification code entity:
```java
public class EmailVerificationCode {
    private String email;
    private String code;
    private Instant expiresAt;
    // Constructor, getters, and setters
}
```

4. Create code repository interface:
```java
public interface EmailCodeRepository {
    void save(String email, String code, Instant expiresAt);
    Optional<EmailVerificationCode> findByEmail(String email);
    void deleteByEmail(String email);
}
```

5. Implement in-memory repository:
```java
public class InMemoryEmailCodeRepository implements EmailCodeRepository {
    private final Map<String, EmailVerificationCode> codes = new ConcurrentHashMap<>();
    // Implementation methods
}
```

6. Create distributed repository using Spring Cache (for cluster support):
```java
@ConditionalOnClass(name = "org.springframework.cache.CacheManager")
public class CacheBackedEmailCodeRepository implements EmailCodeRepository {
    private final CacheManager cacheManager;
    // Implementation methods
}
```

7. Create the email code service:
```java
public interface EmailCodeService {
    void generateAndSendCode(String email);
    boolean verifyCode(String email, String code);
}
```

8. Implement the email code service:
```java
public class EmailCodeServiceImpl implements EmailCodeService {
    private final EmailCodeRepository repository;
    private final JavaMailSender mailSender;
    private final EmailMfaProperties properties;
    private final Random random = new SecureRandom();
    
    // Implementation methods for generating and sending codes
}
```

### Phase 2: MFA Verification Integration

1. Extend `RegisteredUser` interface with email MFA methods:
```java
public interface RegisteredUser {
    // Existing methods...
    
    default MfaType getMfaType() {
        return isMfaConfigured() ? MfaType.TOTP : MfaType.NONE;
    }
    
    default String getMfaEmail() {
        return null;
    }
}
```

2. Create MFA type enum:
```java
public enum MfaType {
    NONE,
    TOTP,
    EMAIL
}
```

3. Implement email verification check:
```java
public class MfaEmailVerificationCheck implements MfaVerificationCheck {
    private final EmailCodeService emailCodeService;
    
    @Override
    public boolean validate(RegisteredUser user, MfaAuthenticationToken authentication) {
        if (user.getMfaType() != MfaType.EMAIL) {
            return false; // Not applicable for this user
        }
        
        String code = authentication.getVerificationCode();
        if (code == null || code.isEmpty()) {
            throw new MfaRequiredException(MfaAuthenticationProvider.SERVER_MFA_CODE_REQUIRED_ERROR);
        }
        
        if (!emailCodeService.verifyCode(user.getMfaEmail(), code)) {
            throw new BadCredentialsException(DefaultLoginAuthenticationExceptionHandler.SERVER_LOGIN_FAILED_ERROR);
        }
        
        return true;
    }
}
```

4. Enhance the `MfaAuthenticationProvider` to handle email MFA:
```java
public class MfaAuthenticationProvider extends DaoAuthenticationProvider {
    // Existing code...
    
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) {
        super.additionalAuthenticationChecks(userDetails, authentication);
        
        if (userDetails instanceof UserDetailsAdapter<? extends RegisteredUser> userDetailsAdapter) {
            RegisteredUser user = userDetailsAdapter.user();
            if (user.getMfaType() == MfaType.EMAIL) {
                // Handle email verification
                if (authentication instanceof MfaAuthenticationToken mfaAuth && 
                   (mfaAuth.getVerificationCode() == null || mfaAuth.getVerificationCode().isEmpty())) {
                    // Send email code when no verification code is provided
                    emailCodeService.generateAndSendCode(user.getMfaEmail());
                    throw new MfaRequiredException(SERVER_MFA_CODE_REQUIRED_ERROR);
                }
            }
            
            if (userDetailsAdapter.isMfaConfigured()) {
                executeMfaVerificationSteps((MfaAuthenticationToken) authentication, userDetailsAdapter);
            } else if (userDetailsAdapter.isMfaMandatory()) {
                authentication.setDetails(DETAILS_MFA_SETUP_REQUIRED);
            }
        }
    }
}
```

### Phase 3: Auto-Configuration Integration

1. Create Email MFA auto-configuration:
```java
@Configuration
@ConditionalOnClass(name = "org.springframework.mail.javamail.JavaMailSender")
@EnableConfigurationProperties(EmailMfaProperties.class)
public class EmailMfaAutoConfig {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rest-secure.mfa.email", name = "enabled", havingValue = "true")
    public EmailCodeRepository emailCodeRepository() {
        return new InMemoryEmailCodeRepository();
    }
    
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rest-secure.mfa.email", name = "enabled", havingValue = "true")
    public EmailCodeService emailCodeService(EmailCodeRepository repository, EmailMfaProperties properties, 
                                             JavaMailSender mailSender) {
        return new EmailCodeServiceImpl(repository, mailSender, properties);
    }
    
    @Bean
    @ConditionalOnBean(EmailCodeService.class)
    public MfaEmailVerificationCheck mfaEmailVerificationCheck(EmailCodeService emailCodeService) {
        return new MfaEmailVerificationCheck(emailCodeService);
    }
}
```

2. Modify existing `MfaSecurityAutoConfig` to ensure the email check is added to verification checks:
```java
@Configuration
@AutoConfigureAfter(name = {"dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration", 
                          "nl._42.restsecure.autoconfigure.EmailMfaAutoConfig"})
public class MfaSecurityAutoConfig {
    // Existing code...
    
    @Bean
    @ConditionalOnMissingBean(name = "mfaAuthenticationProvider")
    @ConditionalOnBean({UserDetailsService.class, PasswordEncoder.class, MfaValidationService.class})
    public MfaAuthenticationProvider mfaAuthenticationProvider(UserDetailsService userDetailsService, 
                                                               PasswordEncoder passwordEncoder,
                                                               MfaValidationService mfaValidationService,
                                                               @Autowired(required = false) List<MfaVerificationCheck> verificationChecks) {
        MfaAuthenticationProvider provider = new MfaAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setMfaValidationService(mfaValidationService);
        
        if (verificationChecks != null && !verificationChecks.isEmpty()) {
            provider.setVerificationChecks(verificationChecks);
        }
        
        return provider;
    }
}
```

3. Update auto-configuration imports file:
```
nl._42.restsecure.autoconfigure.EmailMfaAutoConfig
```

### Phase 4: MFA Setup Service Enhancement

1. Enhance the MFA setup service interface for email MFA:
```java
public interface MfaSetupService {
    // Existing methods...
    
    void setupEmailMfa(String email);
}
```

2. Implement email MFA setup in the service implementation:
```java
public class MfaSetupServiceImpl implements MfaSetupService {
    // Existing code...
    
    private final EmailCodeService emailCodeService;
    
    @Override
    public void setupEmailMfa(String email) {
        // Send a test verification email to confirm the setup
        emailCodeService.generateAndSendCode(email);
    }
}
```

## 4. Testing

### Unit Tests

1. Create unit tests for email code service:
```java
public class EmailCodeServiceImplTest {
    @Test
    public void testGenerateCode() { /* ... */ }
    
    @Test
    public void testVerifyValidCode() { /* ... */ }
    
    @Test
    public void testVerifyExpiredCode() { /* ... */ }
}
```

2. Create unit tests for email verification check:
```java
public class MfaEmailVerificationCheckTest {
    @Test
    public void testValidateWhenEmailMfa() { /* ... */ }
    
    @Test
    public void testValidateWhenNotEmailMfa() { /* ... */ }
    
    @Test
    public void testValidateWithInvalidCode() { /* ... */ }
}
```

3. Create unit tests for email code repositories:
```java
public class InMemoryEmailCodeRepositoryTest {
    @Test
    public void testSaveAndFind() { /* ... */ }
    
    @Test
    public void testDeleteByEmail() { /* ... */ }
}
```

### Integration Tests

1. Create an integration test for the complete authentication flow:
```java
@SpringBootTest
public class EmailMfaAuthenticationFlowTest {
    @Test
    public void testSuccessfulEmailMfaAuthentication() { /* ... */ }
    
    @Test
    public void testAuthenticationWithInvalidCode() { /* ... */ }
    
    @Test
    public void testMfaSetupRequiredFilter() { /* ... */ }
}
```

2. Create test configurations for different MFA scenarios:
```java
@Configuration
public class EmailMfaUserConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        // Return a user with EMAIL MFA configured
    }
}
```

## 5. Documentation

### README Updates

1. Update the "Features" section to include email MFA:
```markdown
- Support for multiple two-factor authentication (2FA) methods:
  * Time-based One-Time Password (TOTP) using authenticator apps
  * Email-based verification codes
```

2. Add a new section for email MFA configuration:
```markdown
### Configuring Email-based MFA

To use email-based MFA, add the following dependency:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
</dependency>
```

Configure email settings in `application.yml`:
```yaml
spring:
  mail:
    host: smtp.example.com
    port: 587
    username: username
    password: password
    properties:
      mail.smtp.auth: true
      mail.smtp.starttls.enable: true

rest-secure:
  mfa:
    email:
      enabled: true
      code-length: 6
      code-validity-seconds: 300
      email-subject: "Your verification code"
      email-from: "security@example.com"
```

Implement the required methods in your User class:
```java
@Override
public MfaType getMfaType() {
    return emailMfaEnabled ? MfaType.EMAIL : 
           totpMfaEnabled ? MfaType.TOTP : MfaType.NONE;
}

@Override
public String getMfaEmail() {
    return email;
}
```
```

3. Update the existing MFA setup instructions for multiple methods:
```markdown
### Implementing MFA configuration endpoints

Your application needs to implement endpoints for MFA configuration:

- Request MFA activation (for TOTP: generates QR code, for Email: sends test email)
- Configure MFA authentication (verify the code and enable the selected MFA method)
- Disable MFA authentication (optional)
- Change MFA method (optional, to switch between TOTP and Email methods)
```

## 6. Conclusion

This implementation plan provides a structured approach to adding email-based MFA to the rest-secure-spring-boot-starter library. The design leverages the existing extension points and follows consistent patterns to ensure compatibility with the current architecture.

Key benefits of this approach:
- Minimum impact on existing code
- Consistent with current design patterns
- Flexible configuration options
- Support for different deployment scenarios
- Clear documentation for library users

Next steps after implementation:
1. Consider adding rate limiting for code generation requests
2. Explore additional MFA methods (SMS, push notifications)
3. Add support for backup codes