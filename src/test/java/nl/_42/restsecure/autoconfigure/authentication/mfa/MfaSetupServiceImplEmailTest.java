package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

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
}