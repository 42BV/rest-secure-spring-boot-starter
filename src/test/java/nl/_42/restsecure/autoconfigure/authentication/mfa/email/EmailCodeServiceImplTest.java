package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@ExtendWith(MockitoExtension.class)
class EmailCodeServiceImplTest {

    private EmailCodeServiceImpl emailCodeService;

    @Mock
    private EmailCodeRepository repository;

    @Mock
    private JavaMailSender mailSender;

    private EmailMfaProperties properties;

    @BeforeEach
    void setUp() {
        properties = new EmailMfaProperties();
        properties.setCodeLength(6);
        properties.setCodeValiditySeconds(300);
        properties.setEmailSubject("Verification Code");
        properties.setEmailFrom("security@example.com");
        properties.setEmailTemplate("Your verification code is: {code}");

        emailCodeService = new EmailCodeServiceImpl(repository, mailSender, properties);
    }

    @Test
    void generateAndSendCode() {
        // Given
        String email = "user@example.com";
        doNothing().when(repository).save(anyString(), anyString(), any(Instant.class));
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailCodeService.generateAndSendCode(email);

        // Then
        ArgumentCaptor<String> emailCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> codeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Instant> expiresAtCaptor = ArgumentCaptor.forClass(Instant.class);
        
        verify(repository).save(emailCaptor.capture(), codeCaptor.capture(), expiresAtCaptor.capture());
        
        String capturedEmail = emailCaptor.getValue();
        String capturedCode = codeCaptor.getValue();
        Instant capturedExpiresAt = expiresAtCaptor.getValue();
        
        assertEquals(email, capturedEmail);
        assertTrue(capturedCode.matches("\\d{6}")); // 6-digit code
        assertTrue(capturedExpiresAt.isAfter(Instant.now()));
        assertTrue(capturedExpiresAt.isBefore(Instant.now().plusSeconds(301)));
        
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());
        
        SimpleMailMessage capturedMessage = messageCaptor.getValue();
        assertEquals(properties.getEmailFrom(), capturedMessage.getFrom());
        assertEquals(email, capturedMessage.getTo()[0]);
        assertEquals(properties.getEmailSubject(), capturedMessage.getSubject());
        assertTrue(capturedMessage.getText().contains(capturedCode));
    }

    @Test
    void verifyCodeValid() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        EmailVerificationCode verificationCode = new EmailVerificationCode(email, code, Instant.now().plusSeconds(60));
        
        when(repository.findByEmail(email)).thenReturn(Optional.of(verificationCode));
        
        // When
        boolean result = emailCodeService.verifyCode(email, code);
        
        // Then
        assertTrue(result);
        verify(repository).deleteByEmail(email);
    }
    
    @Test
    void verifyCodeInvalid() {
        // Given
        String email = "user@example.com";
        String correctCode = "123456";
        String wrongCode = "654321";
        EmailVerificationCode verificationCode = new EmailVerificationCode(email, correctCode, Instant.now().plusSeconds(60));
        
        when(repository.findByEmail(email)).thenReturn(Optional.of(verificationCode));
        
        // When
        boolean result = emailCodeService.verifyCode(email, wrongCode);
        
        // Then
        assertFalse(result);
    }
    
    @Test
    void verifyCodeNotFound() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        
        when(repository.findByEmail(email)).thenReturn(Optional.empty());
        
        // When
        boolean result = emailCodeService.verifyCode(email, code);
        
        // Then
        assertFalse(result);
    }
}