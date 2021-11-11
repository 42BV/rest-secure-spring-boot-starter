package nl._42.restsecure.autoconfigure.authentication.mfa;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;

/**
 * Service which contains logic to set up MFA authentication
 */
public class MfaSetupServiceImpl implements MfaSetupService {

    private final SecretGenerator secretGenerator;
    private final QrDataFactory qrDataFactory;
    private final QrGenerator qrGenerator;
    private final String issuer;

    public MfaSetupServiceImpl(SecretGenerator secretGenerator, QrDataFactory qrDataFactory, QrGenerator qrGenerator, String issuer) {
        this.secretGenerator = secretGenerator;
        this.qrDataFactory = qrDataFactory;
        this.qrGenerator = qrGenerator;
        this.issuer = issuer;
    }

    /**
     * Generates a new MFA secret
     * The secret is to be stored in a secure way for the given user.
     * @return Secret key to generate a QR code and to validate MFA authentication codes.
     */
    public String generateSecret() {
        // Generates a new MFA secret
        return secretGenerator.generate();
    }

    /**
     * Generates a new MFA QR code
     * @param secret Secret key of the user
     * @param label Label to show in the MFA app. This must be something related to the user (e.g. username, email address).
     * @return A base64-encoded DATA URI of the QR code. This can for example be used in a HTML img element.
     * @throws MfaException If the QR code cannot be generated.
     */
    public String generateQrCode(String secret, String label) throws MfaException {
        QrData data = qrDataFactory.newBuilder()
            .label(label)
            .secret(secret)
            .issuer(issuer)
            .build();

        // Generate the QR code image data as a base64 string which
        // can be used in an <img> tag:
        try {
            return getDataUriForImage(
                    qrGenerator.generate(data),
                    qrGenerator.getImageMimeType()
            );
        } catch (QrGenerationException e) {
            throw new MfaException("Unable to generate QR code", e);
        }
    }
}
