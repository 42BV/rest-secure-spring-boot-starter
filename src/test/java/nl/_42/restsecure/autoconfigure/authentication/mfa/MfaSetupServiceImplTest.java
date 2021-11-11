package nl._42.restsecure.autoconfigure.authentication.mfa;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.StringUtils;

class MfaSetupServiceImplTest {

    @Nested
    class generateSecret {

        @Test
        @DisplayName("should call SecretGenerator to generate a new secret")
        void shouldCallSecretGeneratorToGenerateSecret() {
            SecretGenerator mockSecretGenerator = new SecretGenerator() {
                private final AtomicInteger index = new AtomicInteger(1);

                @Override
                public String generate() {
                    return String.valueOf(index.getAndIncrement()).repeat(6);
                }
            };

            MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(mockSecretGenerator, null, null, "Rest-secure");
            assertEquals("111111", setupService.generateSecret());
            assertEquals("222222", setupService.generateSecret());
        }

        @Test
        @DisplayName("should call secret generator to generate a hash")
        void shouldCallRealSecretGEneratorToGenerateHash() {
            MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(new DefaultSecretGenerator(), new QrDataFactory(HashingAlgorithm.SHA1, 6, 1), new ZxingPngQrGenerator(), "Rest-secure");
            String[] secrets = new String[10_000];

            for (int i = 0; i < 10000; i++) {
                secrets[i] = setupService.generateSecret();
            }

            Set<String> distinctSecrets = new HashSet<>(Arrays.asList(secrets));
            assertEquals(10_000, distinctSecrets.size());
            assertTrue(distinctSecrets.stream().noneMatch(secret -> secret == null || StringUtils.isBlank(secret)));
        }
    }

    @Test
    @DisplayName("Encodes generated qr code in base64")
    void generateQrCode() throws MfaException {
        MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(new DefaultSecretGenerator(), new QrDataFactory(HashingAlgorithm.SHA1, 6, 1), new ZxingPngQrGenerator(), "Rest-secure");
        String qr = setupService.generateQrCode(setupService.generateSecret(), "test-user");

        assertTrue(qr.startsWith("data:image/png;base64,"));
    }

    @Test
    @DisplayName("throws mfaException if a qrException is thrown")
    void throwsMfaExceptionWhenCodeCannotBeGenerated() {
        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        QrDataFactory qrDataFactory = new QrDataFactory(HashingAlgorithm.SHA1, 6, 1);
        QrGenerator exceptionThrowingQrGenerator = new QrGenerator() {
            @Override
            public String getImageMimeType() {
                return null;
            }

            @Override
            public byte[] generate(QrData data) throws QrGenerationException {
                throw new QrGenerationException("Not generating your code, today!", new RuntimeException("Test"));
            }
        };
        String issuer = "Test issuer";

        MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(secretGenerator, qrDataFactory, exceptionThrowingQrGenerator, issuer);

        MfaException exception = assertThrows(MfaException.class, () -> setupService.generateQrCode("very-secret", "something-special"));
        assertEquals("Unable to generate QR code", exception.getMessage());
        assertEquals(QrGenerationException.class, exception.getCause().getClass());
        assertEquals("Not generating your code, today!", exception.getCause().getMessage());
        assertEquals(RuntimeException.class, exception.getCause().getCause().getClass());
        assertEquals("Test", exception.getCause().getCause().getMessage());
    }
}
