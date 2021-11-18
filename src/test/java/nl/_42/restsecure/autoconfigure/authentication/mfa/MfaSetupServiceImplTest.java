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
            MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(new DefaultSecretGenerator(), new QrDataFactory(HashingAlgorithm.SHA1, 6, 30), new ZxingPngQrGenerator(), "Rest-secure");
            String[] secrets = new String[10_000];

            for (int i = 0; i < 10000; i++) {
                secrets[i] = setupService.generateSecret();
            }

            Set<String> distinctSecrets = new HashSet<>(Arrays.asList(secrets));
            assertEquals(10_000, distinctSecrets.size());
            assertTrue(distinctSecrets.stream().noneMatch(secret -> secret == null || StringUtils.isBlank(secret)));
        }
    }

    @Nested
    class generateQrCode {
        @Test
        @DisplayName("Encodes generated qr code in base64")
        void generatesQrCode() throws MfaException {
            MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(new DefaultSecretGenerator(), new QrDataFactory(HashingAlgorithm.SHA1, 6, 30), new ZxingPngQrGenerator(), "Rest-secure");
            String qr = setupService.generateQrCode(setupService.generateSecret(), "test-user");

            assertTrue(qr.startsWith("data:image/png;base64,"));
        }

        @Test
        @DisplayName("Calls qrGenerator with the right arguments (label, issuer, etc.")
        void usesCorrectMetadata() throws MfaException {
            final QrData[] qrDataHolder = new QrData[1];

            String exampleSecret = "XK6PZWX6RK46LBGRXSYRN7RE2X56UQD7";
            SecretGenerator mockSecretGenerator = () -> exampleSecret;

            ZxingPngQrGenerator zxingPngQrGenerator = new ZxingPngQrGenerator();
            QrGenerator mockQrGenerator = new QrGenerator() {
                @Override
                public String getImageMimeType() {
                    return "image/png";
                }

                @Override
                public byte[] generate(QrData data) throws QrGenerationException {
                    qrDataHolder[0] = data;
                    return zxingPngQrGenerator.generate(data);
                }
            };

            String issuer = "Rest-secure Test Issuer";

            MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(mockSecretGenerator, new QrDataFactory(HashingAlgorithm.SHA1, 6, 30), mockQrGenerator, issuer);

            String labelWithoutIssuer = "fake-issuer:test-user@example.com";
            String qr = setupService.generateQrCode(setupService.generateSecret(), labelWithoutIssuer);
            assertTrue(qr.startsWith("data:image/png;base64,"));

            QrData generatedQrData = qrDataHolder[0];

            assertNotNull(generatedQrData);
            assertEquals(issuer, generatedQrData.getIssuer());
            assertEquals("Rest-secure Test Issuer:fake-issuer:test-user@example.com", generatedQrData.getLabel());
            assertEquals(exampleSecret, generatedQrData.getSecret());
            assertEquals("totp", generatedQrData.getType());
            assertEquals("SHA1", generatedQrData.getAlgorithm());
            assertEquals(30, generatedQrData.getPeriod());
            assertEquals(6, generatedQrData.getDigits());
            assertEquals("otpauth://totp/Rest-secure%20Test%20Issuer%3Afake-issuer%3Atest-user%40example.com?secret=XK6PZWX6RK46LBGRXSYRN7RE2X56UQD7&issuer=Rest-secure%20Test%20Issuer&algorithm=SHA1&digits=6&period=30", generatedQrData.getUri());

            // Generate a QR with the issuer already in the label, this should not add the issuer again.
            String labelWithIssuer = "Rest-secure Test Issuer:test-user@example.com";
            setupService.generateQrCode(setupService.generateSecret(), labelWithIssuer);
            generatedQrData = qrDataHolder[0];

            assertNotNull(generatedQrData);
            assertEquals(issuer, generatedQrData.getIssuer());
            assertEquals(labelWithIssuer, generatedQrData.getLabel());
            assertEquals(exampleSecret, generatedQrData.getSecret());
            assertEquals("totp", generatedQrData.getType());
            assertEquals("SHA1", generatedQrData.getAlgorithm());
            assertEquals(30, generatedQrData.getPeriod());
            assertEquals(6, generatedQrData.getDigits());
            assertEquals("otpauth://totp/Rest-secure%20Test%20Issuer%3Atest-user%40example.com?secret=XK6PZWX6RK46LBGRXSYRN7RE2X56UQD7&issuer=Rest-secure%20Test%20Issuer&algorithm=SHA1&digits=6&period=30", generatedQrData.getUri());

        }

        @Test
        @DisplayName("throws if label is null or empty")
        void throwsForMissingLabel() {
            MfaSetupServiceImpl setupService = new MfaSetupServiceImpl(new DefaultSecretGenerator(), new QrDataFactory(HashingAlgorithm.SHA1, 6, 30), new ZxingPngQrGenerator(), "Rest-secure");
            MfaException e1 = assertThrows(MfaException.class, () -> setupService.generateQrCode(setupService.generateSecret(), null));
            MfaException e2 = assertThrows(MfaException.class, () -> setupService.generateQrCode(setupService.generateSecret(), ""));

            assertEquals("Label cannot be blank!", e1.getMessage());
            assertEquals("Label cannot be blank!", e2.getMessage());
            assertNull(e1.getCause());
            assertNull(e2.getCause());
        }
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
