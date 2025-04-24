package nl._42.restsecure.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupServiceImpl;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationServiceImpl;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaVerificationCheck;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Auto-configures beans for MFA validation and configuration. These beans are dependent on the beans defined in {@link dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration}.
 */
@Configuration
@ConditionalOnClass(name = "dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration")
@AutoConfigureAfter(name = {"dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration", 
                          "nl._42.restsecure.autoconfigure.EmailMfaAutoConfig"})
public class MfaSecurityAutoConfig {

    @Bean
    @ConditionalOnMissingBean(MfaValidationService.class)
    @ConditionalOnBean(type = "dev.samstevens.totp.code.CodeVerifier")
    public MfaValidationService mfaValidationService(dev.samstevens.totp.code.CodeVerifier codeVerifier) {
        return new MfaValidationServiceImpl(codeVerifier);
    }

    @Bean
    @ConditionalOnMissingBean(MfaSetupService.class)
    @ConditionalOnBean(type = {"dev.samstevens.totp.secret.SecretGenerator", "dev.samstevens.totp.qr.QrDataFactory", "dev.samstevens.totp.qr.QrGenerator"})
    public MfaSetupService mfaSetupService(dev.samstevens.totp.secret.SecretGenerator secretGenerator, 
                                         dev.samstevens.totp.qr.QrDataFactory qrDataFactory, 
                                         dev.samstevens.totp.qr.QrGenerator qrGenerator, 
                                         @Value("${totp.issuer:needs-totp-issuer}") String issuer,
                                         @Autowired(required = false) EmailCodeService emailCodeService) {
        return new MfaSetupServiceImpl(secretGenerator, qrDataFactory, qrGenerator, issuer, emailCodeService);
    }
    
    @Bean
    @ConditionalOnMissingBean(name = "mfaAuthenticationProvider")
    @ConditionalOnBean({UserDetailsService.class, PasswordEncoder.class, MfaValidationService.class})
    public MfaAuthenticationProvider mfaAuthenticationProvider(UserDetailsService userDetailsService, 
                                                             PasswordEncoder passwordEncoder,
                                                             MfaValidationService mfaValidationService,
                                                             @Autowired(required = false) List<MfaVerificationCheck> verificationChecks,
                                                             @Autowired(required = false) EmailCodeService emailCodeService) {
        MfaAuthenticationProvider provider = new MfaAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setMfaValidationService(mfaValidationService);
        
        if (emailCodeService != null) {
            provider.setEmailCodeService(emailCodeService);
        }
        
        if (verificationChecks != null && !verificationChecks.isEmpty()) {
            provider.setVerificationChecks(verificationChecks);
        }
        
        return provider;
    }
}
