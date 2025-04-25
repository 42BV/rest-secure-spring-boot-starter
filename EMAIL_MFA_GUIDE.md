# Email MFA Implementation Guide

This guide explains how to implement email-based Multi-Factor Authentication (MFA) in your Spring Boot application using the rest-secure-spring-boot-starter library.

## Overview

Email MFA provides a second verification step during login by sending a verification code to the user's email address. This implementation works alongside the existing Time-based One-Time Password (TOTP) MFA option.

## Setup Requirements

1. A Spring Boot application
2. Email sending capabilities (Spring Mail)
3. rest-secure-spring-boot-starter dependency

## Configuration Steps

### 1. Add Dependencies

Ensure you have the necessary dependencies in your pom.xml:

```xml
<dependency>
    <groupId>nl.42</groupId>
    <artifactId>rest-secure-spring-boot-starter</artifactId>
    <version>X.Y.Z</version>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
</dependency>
```

### 2. Configure Email Settings

Add the following properties to your `application.properties` or `application.yml`:

```properties
# Spring Mail Configuration
spring.mail.host=your-smtp-server
spring.mail.port=587
spring.mail.username=your-username
spring.mail.password=your-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

# Email MFA Configuration
rest-secure.mfa.email.enabled=true
rest-secure.mfa.email.code-length=6
rest-secure.mfa.email.code-validity-seconds=300
rest-secure.mfa.email.email-subject=Your verification code
rest-secure.mfa.email.email-from=security@your-domain.com
rest-secure.mfa.email.email-template=Your verification code is: {code}
```

### 3. Cache Configuration (Optional but Recommended)

For production, configure a cache to store verification codes:

```java
@Configuration
@EnableCaching
public class CacheConfig {
    
    @Bean
    public CacheManager cacheManager() {
        SimpleCacheManager cacheManager = new SimpleCacheManager();
        cacheManager.setCaches(Collections.singletonList(
                new ConcurrentMapCache("emailVerificationCodes")
        ));
        return cacheManager;
    }
}
```

### 4. Implement User Entity

Your user entity must implement the `RegisteredUser` interface and provide methods for email MFA:

```java
public class User implements RegisteredUser {
    
    private String username;
    private String password;
    private Set<String> authorities;
    private boolean enabled = true;
    private MfaType mfaType = MfaType.NONE;
    private String mfaEmail;
    private String mfaSecretKey;
    
    // Standard getters and setters...
    
    @Override
    public String getUsername() {
        return username;
    }
    
    @Override
    public String getPassword() {
        return password;
    }
    
    @Override
    public Set<String> getAuthorities() {
        return authorities;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    
    @Override
    public boolean isMfaConfigured() {
        return mfaType != MfaType.NONE;
    }
    
    @Override
    public String getMfaSecretKey() {
        return mfaType == MfaType.TOTP ? mfaSecretKey : null;
    }
    
    @Override
    public MfaType getMfaType() {
        return mfaType;
    }
    
    @Override
    public String getMfaEmail() {
        return mfaType == MfaType.EMAIL ? mfaEmail : null;
    }
}
```

### 5. Create MFA Setup Controller

Add a controller for setting up email MFA:

```java
@RestController
@RequestMapping("/api/mfa")
public class MfaSetupController {
    
    private final MfaSetupService mfaSetupService;
    private final UserService userService; // Your own service to update user info
    
    public MfaSetupController(MfaSetupService mfaSetupService, UserService userService) {
        this.mfaSetupService = mfaSetupService;
        this.userService = userService;
    }
    
    @PostMapping("/email/setup")
    public void setupEmailMfa(@RequestBody EmailMfaSetupRequest request,
                              @CurrentUser RegisteredUser currentUser) {
        // Initialize setup by sending verification code
        mfaSetupService.setupEmailMfa(request.getEmail());
    }
    
    @PostMapping("/email/verify")
    public void verifyEmailMfa(@RequestBody EmailMfaVerifyRequest request,
                               @CurrentUser RegisteredUser currentUser) {
        // Verify the code and if successful, enable email MFA for the user
        boolean isValid = mfaSetupService.verifyEmailMfaSetup(request.getEmail(), request.getCode());
        
        if (isValid) {
            userService.updateUserMfaSettings(
                    currentUser.getUsername(),
                    MfaType.EMAIL,
                    request.getEmail());
        } else {
            throw new BadRequestException("Invalid verification code");
        }
    }
    
    // Request DTOs
    @Data
    static class EmailMfaSetupRequest {
        private String email;
    }
    
    @Data
    static class EmailMfaVerifyRequest {
        private String email;
        private String code;
    }
}
```

### 6. Frontend Implementation

Your frontend needs to:

1. Allow users to set up email MFA
2. Handle the login flow when MFA is required
3. Present an interface for entering the verification code

#### Example login flow on the frontend:

```javascript
// Typical login POST request
async function login(username, password) {
  try {
    const response = await fetch('/api/authentication/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, verificationCode: null })
    });
    
    if (response.status === 200) {
      // Login successful
      return { success: true };
    } else if (response.status === 428) {
      // MFA required - check user MFA type and show appropriate screen
      const mfaInfo = await response.json();
      return { 
        success: false, 
        requiresMfa: true,
        mfaType: mfaInfo.mfaType // Could be "EMAIL" or "TOTP"
      };
    } else {
      // Other error
      return { success: false, error: 'Login failed' };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Complete login with verification code
async function completeLogin(username, password, verificationCode) {
  try {
    const response = await fetch('/api/authentication/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, verificationCode })
    });
    
    if (response.status === 200) {
      // Login successful
      return { success: true };
    } else {
      // Error (invalid code, etc)
      return { success: false, error: 'Invalid verification code' };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}
```

## Troubleshooting

### Common Issues:

1. **Verification emails not sending**
   - Check Spring Mail configuration
   - Verify SMTP server connectivity
   - Check if email-from property is set correctly

2. **Verification codes not being recognized**
   - Check if code expiration time is sufficient
   - Verify the code format matches what's expected
   - Make sure your cache is configured correctly

3. **Users unable to set up email MFA**
   - Check that the necessary components are wired together
   - Verify user model properly implements RegisteredUser interface
   - Check permissions on the MFA setup endpoints

## Additional Features

### Custom Email Templates

You can customize the email template using HTML:

```properties
rest-secure.mfa.email.email-template=<html><body><h1>Verification Code</h1><p>Your code is: {code}</p></body></html>
```

### Email MFA Recovery

Consider implementing a recovery flow for cases where users lose access to their email, such as:
- Using backup codes
- Security questions
- Alternative verification methods