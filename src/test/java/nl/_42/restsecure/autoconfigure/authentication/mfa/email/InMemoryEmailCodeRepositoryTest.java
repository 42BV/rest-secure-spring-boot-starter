package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InMemoryEmailCodeRepositoryTest {

    private InMemoryEmailCodeRepository repository;
    
    @BeforeEach
    void setUp() {
        repository = new InMemoryEmailCodeRepository();
    }
    
    @Test
    void saveAndFind() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        Instant expiresAt = Instant.now().plusSeconds(300);
        
        // When
        repository.save(email, code, expiresAt);
        Optional<EmailVerificationCode> result = repository.findByEmail(email);
        
        // Then
        assertTrue(result.isPresent());
        assertEquals(email, result.get().getEmail());
        assertEquals(code, result.get().getCode());
        assertEquals(expiresAt, result.get().getExpiresAt());
    }
    
    @Test
    void findByEmailWhenExpired() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        Instant expiresAt = Instant.now().minusSeconds(60); // Already expired
        
        // When
        repository.save(email, code, expiresAt);
        Optional<EmailVerificationCode> result = repository.findByEmail(email);
        
        // Then
        assertFalse(result.isPresent());
    }
    
    @Test
    void deleteByEmail() {
        // Given
        String email = "user@example.com";
        String code = "123456";
        Instant expiresAt = Instant.now().plusSeconds(300);
        
        // When
        repository.save(email, code, expiresAt);
        repository.deleteByEmail(email);
        Optional<EmailVerificationCode> result = repository.findByEmail(email);
        
        // Then
        assertFalse(result.isPresent());
    }
}