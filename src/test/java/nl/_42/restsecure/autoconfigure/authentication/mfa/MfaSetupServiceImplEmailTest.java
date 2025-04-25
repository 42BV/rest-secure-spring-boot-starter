package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MfaSetupServiceImplEmailTest {

    private MfaSetupServiceImpl service;
    
    @Mock
    private SecretGenerator secretGenerator;
    
    @Mock
    private QrDataFactory qrDataFactory;
    
    @Mock
    private QrGenerator qrGenerator;
    
    @Mock
    private EmailCodeService emailCodeService;
    
    @BeforeEach
    void setUp() {
        service = new MfaSetupServiceImpl(secretGenerator, qrDataFactory, qrGenerator, "TestIssuer", emailCodeService);
    }
    
    @Test
    void setupEmailMfa() {
        // Given
        String email = "user@example.com";
        
        // When
        service.setupEmailMfa(email);
        
        // Then
        verify(emailCodeService).generateAndSendCode(email);
    }
    
    @Test
    void setupEmailMfaWithNullEmail() {
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.setupEmailMfa(null);
        });
    }
    
    @Test
    void setupEmailMfaWithEmptyEmail() {
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.setupEmailMfa("");
        });
    }
    
    @Test
    void setupEmailMfaWithNullEmailCodeService() {
        // Given
        service = new MfaSetupServiceImpl(secretGenerator, qrDataFactory, qrGenerator, "TestIssuer");
        
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.setupEmailMfa("user@example.com");
        });
    }
    
    @Test
    void verifyEmailMfaSetup_valid() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        when(emailCodeService.verifyCode(email, code)).thenReturn(true);
        
        // When
        boolean result = service.verifyEmailMfaSetup(email, code);
        
        // Then
        assertTrue(result);
        verify(emailCodeService).verifyCode(email, code);
    }
    
    @Test
    void verifyEmailMfaSetup_invalid() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        when(emailCodeService.verifyCode(email, code)).thenReturn(false);
        
        // When
        boolean result = service.verifyEmailMfaSetup(email, code);
        
        // Then
        assertFalse(result);
        verify(emailCodeService).verifyCode(email, code);
    }
    
    @Test
    void verifyEmailMfaSetup_withNullEmail() {
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.verifyEmailMfaSetup(null, "123456");
        });
    }
    
    @Test
    void verifyEmailMfaSetup_withEmptyEmail() {
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.verifyEmailMfaSetup("", "123456");
        });
    }
    
    @Test
    void verifyEmailMfaSetup_withNullCode() {
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.verifyEmailMfaSetup("user@example.com", null);
        });
    }
    
    @Test
    void verifyEmailMfaSetup_withEmptyCode() {
        // Then
        assertThrows(MfaException.class, () -> {
            // When
            service.verifyEmailMfaSetup("user@example.com", "");
        });
    }
}