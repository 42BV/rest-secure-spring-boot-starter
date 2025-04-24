package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationToken;
import nl._42.restsecure.autoconfigure.authentication.mfa.MfaType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@ExtendWith(MockitoExtension.class)
class MfaEmailVerificationCheckTest {

    private MfaEmailVerificationCheck verificationCheck;
    
    @Mock
    private EmailCodeService emailCodeService;
    
    @Mock
    private RegisteredUser user;
    
    @BeforeEach
    void setUp() {
        verificationCheck = new MfaEmailVerificationCheck(emailCodeService);
    }
    
    @Test
    void validateWhenEmailMfa() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        
        when(user.getMfaType()).thenReturn(MfaType.EMAIL);
        when(user.getMfaEmail()).thenReturn(email);
        when(emailCodeService.verifyCode(email, code)).thenReturn(true);
        
        MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", code);
        
        // When
        boolean result = verificationCheck.validate(user, token);
        
        // Then
        assertTrue(result);
        verify(emailCodeService).verifyCode(email, code);
    }
    
    @Test
    void validateWhenEmailMfaInvalidCode() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        
        when(user.getMfaType()).thenReturn(MfaType.EMAIL);
        when(user.getMfaEmail()).thenReturn(email);
        when(emailCodeService.verifyCode(email, code)).thenReturn(false);
        
        MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", code);
        
        // Then
        assertThrows(BadCredentialsException.class, () -> {
            // When
            verificationCheck.validate(user, token);
        });
    }
    
    @Test
    void validateWhenNotEmailMfa() {
        // Given
        when(user.getMfaType()).thenReturn(MfaType.TOTP);
        
        MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
        
        // When
        boolean result = verificationCheck.validate(user, token);
        
        // Then
        assertFalse(result);
        verify(emailCodeService, never()).verifyCode(any(), any());
    }
    
    @Test
    void validateWhenNullEmail() {
        // Given
        when(user.getMfaType()).thenReturn(MfaType.EMAIL);
        when(user.getMfaEmail()).thenReturn(null);
        
        MfaAuthenticationToken token = new MfaAuthenticationToken("username", "password", "123456");
        
        // Then
        assertThrows(IllegalStateException.class, () -> {
            // When
            verificationCheck.validate(user, token);
        });
    }
}