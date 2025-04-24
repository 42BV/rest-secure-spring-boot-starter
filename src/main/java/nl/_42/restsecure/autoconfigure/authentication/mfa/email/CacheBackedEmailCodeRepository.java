package nl._42.restsecure.autoconfigure.authentication.mfa.email;

import java.time.Instant;
import java.util.Optional;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

public class CacheBackedEmailCodeRepository implements EmailCodeRepository {
    private static final String CACHE_NAME = "emailVerificationCodes";
    private final CacheManager cacheManager;

    public CacheBackedEmailCodeRepository(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    @Override
    public void save(String email, String code, Instant expiresAt) {
        getCache().put(email, new EmailVerificationCode(email, code, expiresAt));
    }

    @Override
    public Optional<EmailVerificationCode> findByEmail(String email) {
        Cache.ValueWrapper wrapper = getCache().get(email);
        if (wrapper == null) {
            return Optional.empty();
        }
        
        EmailVerificationCode code = (EmailVerificationCode) wrapper.get();
        if (code.isExpired()) {
            deleteByEmail(email);
            return Optional.empty();
        }
        
        return Optional.of(code);
    }

    @Override
    public void deleteByEmail(String email) {
        getCache().evict(email);
    }
    
    private Cache getCache() {
        Cache cache = cacheManager.getCache(CACHE_NAME);
        if (cache == null) {
            throw new IllegalStateException("Cache '" + CACHE_NAME + "' not found");
        }
        return cache;
    }
}