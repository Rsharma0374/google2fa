package in.guardianservice.google2fa.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import in.guardianservice.google2fa.exception.GoogleAuthenticatorException;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class for generating QR codes for Google Authenticator
 */
public class QRCodeUtil {

    private static final int QR_CODE_WIDTH = 300;
    private static final int QR_CODE_HEIGHT = 300;

    /**
     * Generate QR code URL for Google Authenticator
     * Format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER
     *
     * @param accountName User's account name/email
     * @param secret Base32 encoded secret
     * @param issuer Application/service name
     * @return QR code URL string
     */
    public static String generateQRCodeUrl(String accountName, String secret, String issuer) {
        try {
            String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
            String encodedAccount = URLEncoder.encode(accountName, StandardCharsets.UTF_8);

            return String.format(
                    "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                    encodedIssuer,
                    encodedAccount,
                    secret,
                    encodedIssuer
            );
        } catch (Exception e) {
            throw new GoogleAuthenticatorException("Failed to generate QR code URL", e);
        }
    }

    /**
     * Generate QR code image as Base64 PNG
     *
     * @param data QR code content (typically the otpauth:// URL)
     * @return Base64 encoded PNG image
     */
    public static String generateQRCodeImage(String data) {
        try {
            BitMatrix bitMatrix = new MultiFormatWriter().encode(
                    data,
                    BarcodeFormat.QR_CODE,
                    QR_CODE_WIDTH,
                    QR_CODE_HEIGHT
            );

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

            byte[] imageBytes = outputStream.toByteArray();
            return Base64.getEncoder().encodeToString(imageBytes);
        } catch (Exception e) {
            throw new GoogleAuthenticatorException("Failed to generate QR code image", e);
        }
    }

    /**
     * Generate complete QR code as Base64 PNG image with data URL prefix
     * Ready to be used in <img> src attribute
     *
     * @param accountName User's account name/email
     * @param secret Base32 encoded secret
     * @param issuer Application/service name
     * @return Data URL with Base64 encoded PNG image
     */
    public static String generateQRCodeDataUrl(String accountName, String secret, String issuer) {
        String qrUrl = generateQRCodeUrl(accountName, secret, issuer);
        String base64Image = generateQRCodeImage(qrUrl);
        return "data:image/png;base64," + base64Image;
    }
}
