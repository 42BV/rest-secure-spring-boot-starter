package nl._42.restsecure.autoconfigure;

import static org.junit.jupiter.api.Assertions.*;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupRequiredFilter;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaSetupServiceImpl;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationService;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaValidationServiceImpl;
import nl._42.restsecure.autoconfigure.test.MfaAuthenticationConfig;
import nl._42.restsecure.autoconfigure.test.MockMfaAuthenticationConfig;

import org.junit.jupiter.api.Test;

class MfaSecurityAutoConfigTest extends AbstractApplicationContextTest {


    @Test
    public void autoConfig_shouldConfigureMfaServices() {
        loadApplicationContext(MfaAuthenticationConfig.class);
        this.context.refresh();

        MfaSetupService mfaSetupService = context.getBean(MfaSetupService.class);
        assertEquals(MfaSetupServiceImpl.class, mfaSetupService.getClass());

        MfaValidationService mfaValidationService = context.getBean(MfaValidationService.class);
        assertEquals(MfaValidationServiceImpl.class, mfaValidationService.getClass());

        MfaAuthenticationProvider mfaAuthenticationProvider = context.getBean(MfaAuthenticationProvider.class);
        assertEquals(MfaAuthenticationProvider.class, mfaAuthenticationProvider.getClass());

        MfaSetupRequiredFilter mfaSetupRequiredFilter = context.getBean(MfaSetupRequiredFilter.class);
        assertEquals(MfaSetupRequiredFilter.class, mfaSetupRequiredFilter.getClass());

        CodeVerifier codeVerifier = context.getBean(CodeVerifier.class);
        assertEquals(DefaultCodeVerifier.class, codeVerifier.getClass());

        SecretGenerator secretGenerator = context.getBean(SecretGenerator.class);
        assertEquals(DefaultSecretGenerator.class, secretGenerator.getClass());

        QrGenerator qrGenerator = context.getBean(QrGenerator.class);
        assertEquals(ZxingPngQrGenerator.class, qrGenerator.getClass());
    }
}
