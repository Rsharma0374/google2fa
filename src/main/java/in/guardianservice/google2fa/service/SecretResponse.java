package in.guardianservice.google2fa.service;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response DTO for secret generation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecretResponse {

    /**
     * Base32 encoded secret key (to be stored by user or shown for manual entry)
     */
    private String secret;

    /**
     * QR code as data URL (data:image/png;base64,...)
     * Can be directly used in HTML <img> tag
     */
    private String qrCodeDataUrl;

    /**
     * QR code URL string (otpauth://totp/...)
     * Can be used to generate QR code separately
     */
    private String qrCodeUrl;

    /**
     * Backup codes for account recovery
     */
    private List<String> backupCodes;

    /**
     * User ID
     */
    private String userId;

    /**
     * Service ID
     */
    private String serviceId;
}
