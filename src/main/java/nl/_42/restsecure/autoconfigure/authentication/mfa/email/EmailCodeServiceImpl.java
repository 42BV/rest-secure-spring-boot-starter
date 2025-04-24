package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;
import java.util.Random;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.Assert;

public class EmailCodeServiceImpl implements EmailCodeService {
    private final EmailCodeRepository repository;
    private final JavaMailSender mailSender;
    private final EmailMfaProperties properties;
    private final Random random = new SecureRandom();
    
    public EmailCodeServiceImpl(EmailCodeRepository repository, JavaMailSender mailSender, EmailMfaProperties properties) {
        this.repository = repository;
        this.mailSender = mailSender;
        this.properties = properties;
        
        Assert.notNull(properties.getEmailFrom(), "Email 'from' address must be configured");
    }
    
    @Override
    public void generateAndSendCode(String email) {
        String code = generateCode();
        Instant expiresAt = Instant.now().plusSeconds(properties.getCodeValiditySeconds());
        
        repository.save(email, code, expiresAt);
        sendVerificationEmail(email, code);
    }
    
    @Override
    public boolean verifyCode(String email, String code) {
        Optional<EmailVerificationCode> storedCode = repository.findByEmail(email);
        
        if (storedCode.isEmpty()) {
            return false;
        }
        
        boolean isValid = storedCode.get().getCode().equals(code);
        if (isValid) {
            repository.deleteByEmail(email);
        }
        
        return isValid;
    }
    
    private String generateCode() {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < properties.getCodeLength(); i++) {
            code.append(random.nextInt(10));
        }
        return code.toString();
    }
    
    private void sendVerificationEmail(String email, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.getEmailFrom());
        message.setTo(email);
        message.setSubject(properties.getEmailSubject());
        message.setText(properties.getEmailTemplate().replace("{code}", code));
        
        mailSender.send(message);
    }
}