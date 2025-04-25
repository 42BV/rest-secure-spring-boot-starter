package nl._42.restsecure.autoconfigure;

import nl._42.restsecure.autoconfigure.authentication.mfa.email.CacheBackedEmailCodeRepository;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeRepository;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeService;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailCodeServiceImpl;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.EmailMfaProperties;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.InMemoryEmailCodeRepository;
import nl._42.restsecure.autoconfigure.authentication.mfa.email.MfaEmailVerificationCheck;

import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.SearchStrategy;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
@ConditionalOnClass(JavaMailSender.class)
@EnableConfigurationProperties(EmailMfaProperties.class)
public class EmailMfaAutoConfig {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rest-secure.mfa.email", name = "enabled", havingValue = "true")
    @ConditionalOnBean(CacheManager.class)
    public EmailCodeRepository cacheBackedEmailCodeRepository(CacheManager cacheManager) {
        return new CacheBackedEmailCodeRepository(cacheManager);
    }
    
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rest-secure.mfa.email", name = "enabled", havingValue = "true")
    @ConditionalOnBean(name = "cacheBackedEmailCodeRepository", value = EmailCodeRepository.class, search = SearchStrategy.ANCESTORS)
    public boolean useCacheEmailRepo() {
        // This is a marker bean to indicate we're using the cache-backed repository
        return true;
    }
    
    @Bean
    @ConditionalOnProperty(prefix = "rest-secure.mfa.email", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean(name = "useCacheEmailRepo")
    public EmailCodeRepository inMemoryEmailCodeRepository() {
        return new InMemoryEmailCodeRepository();
    }
    
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rest-secure.mfa.email", name = "enabled", havingValue = "true")
    @ConditionalOnBean(JavaMailSender.class)
    public EmailCodeService emailCodeService(EmailCodeRepository repository, EmailMfaProperties properties, 
                                           JavaMailSender mailSender) {
        return new EmailCodeServiceImpl(repository, mailSender, properties);
    }
    
    @Bean
    @ConditionalOnBean(EmailCodeService.class)
    public MfaEmailVerificationCheck mfaEmailVerificationCheck(EmailCodeService emailCodeService) {
        return new MfaEmailVerificationCheck(emailCodeService);
    }
}