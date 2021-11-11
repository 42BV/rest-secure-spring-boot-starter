package nl._42.restsecure.autoconfigure;

import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupServiceImpl;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationServiceImpl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configures beans for MFA validation and configuration. These beans are dependent on the beans defined in {@link dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration}.
 */
@Configuration
@ConditionalOnClass(name = "dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration")
@AutoConfigureAfter(name = "dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration")
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
    public MfaSetupService mfaSetupService(dev.samstevens.totp.secret.SecretGenerator secretGenerator, dev.samstevens.totp.qr.QrDataFactory qrDataFactory, dev.samstevens.totp.qr.QrGenerator qrGenerator, @Value("${totp.issuer:needs-totp-issuer}") String issuer) {
        return new MfaSetupServiceImpl(secretGenerator, qrDataFactory, qrGenerator, issuer);
    }
}
