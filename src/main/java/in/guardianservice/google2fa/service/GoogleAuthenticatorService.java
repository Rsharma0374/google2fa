package in.guardianservice.google2fa.service;

//import in.guardianservice.google2fa.config.GoogleAuthenticatorConfig;
import in.guardianservice.google2fa.entity.TotpSecret;
import in.guardianservice.google2fa.exception.AccountLockedException;
import in.guardianservice.google2fa.exception.GoogleAuthenticatorException;
import in.guardianservice.google2fa.exception.InvalidCodeException;
import in.guardianservice.google2fa.exception.SecretNotFoundException;
import in.guardianservice.google2fa.repository.TotpSecretRepository;
import in.guardianservice.google2fa.util.EncryptionUtil;
import in.guardianservice.google2fa.util.QRCodeUtil;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.KeyRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Main service for Google Authenticator/TOTP operations
 */
@Service
public class GoogleAuthenticatorService {

    private static final Logger logger = LoggerFactory.getLogger(GoogleAuthenticatorService.class);
    public static final String ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private final TotpSecretRepository repository;
    private final GoogleAuthenticator googleAuthenticator;
    private final EncryptionUtil encryptionUtil;
    private final in.guardianservice.google2fa.config.GoogleAuthenticatorConfig config;
    private final SecureRandom secureRandom;

    public GoogleAuthenticatorService(
            TotpSecretRepository repository,
            in.guardianservice.google2fa.config.GoogleAuthenticatorConfig config) {
        this.repository = repository;
        this.config = config;
        this.encryptionUtil = new EncryptionUtil(config.getEncryptionKey());
        this.secureRandom = new SecureRandom();

        // Configure Google Authenticator
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder configBuilder =
                new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                        .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30))
                        .setWindowSize(config.getTimeWindow())
                        .setCodeDigits(config.getCodeDigits())
                        .setKeyRepresentation(KeyRepresentation.BASE32);

        this.googleAuthenticator = new GoogleAuthenticator(configBuilder.build());
    }

    /**
     * Generate a new TOTP secret for a user
     *
     * @param userId User identifier from calling service
     * @param serviceId Service identifier for multi-tenancy
     * @param accountName User's email or account name for QR code
     * @return SecretResponse containing secret, QR code, and backup codes
     */
    @Transactional
    public SecretResponse generateSecret(String userId, String serviceId, String accountName) {
        logger.info("Generating TOTP secret for user: {} in service: {}", userId, serviceId);

        // Check if user already has a secret
        Optional<TotpSecret> existing = repository.findByUserIdAndServiceId(userId, serviceId);
        if (existing.isPresent() && existing.get().getEnabled()) {
            throw new GoogleAuthenticatorException(
                    "User already has 2FA enabled. Disable existing 2FA before generating a new secret."
            );
        }

        // Generate new secret
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        String secretKey = key.getKey();

        // Generate backup codes
        List<String> backupCodes = generateBackupCodes(8);
        String encryptedBackupCodes = encryptionUtil.encrypt(String.join(",", backupCodes));

        // Encrypt and save
        String encryptedSecret = encryptionUtil.encrypt(secretKey);

        TotpSecret totpSecret = existing.orElse(TotpSecret.builder()
                .userId(userId)
                .serviceId(serviceId)
                .build());

        totpSecret.setEncryptedSecret(encryptedSecret);
        totpSecret.setEnabled(true);
        totpSecret.setBackupCodes(encryptedBackupCodes);
        totpSecret.setFailedAttempts(0);
        totpSecret.setLockedUntil(null);

        repository.save(totpSecret);

        // Generate QR code
        String qrCodeUrl = QRCodeUtil.generateQRCodeUrl(accountName, secretKey, config.getIssuerName());
        String qrCodeDataUrl = QRCodeUtil.generateQRCodeDataUrl(accountName, secretKey, config.getIssuerName());

        logger.info("Successfully generated TOTP secret for user: {} in service: {}", userId, serviceId);

        return SecretResponse.builder()
                .secret(secretKey)
                .qrCodeUrl(qrCodeUrl)
                .qrCodeDataUrl(qrCodeDataUrl)
                .backupCodes(backupCodes)
                .userId(userId)
                .serviceId(serviceId)
                .build();
    }

    /**
     * Validate a TOTP code for a user
     *
     * @param userId User identifier
     * @param code TOTP code to validate
     * @param serviceId Service identifier
     * @return ValidationResponse with validation result
     */
    @Transactional
    public ValidationResponse validateCode(String userId, String code, String serviceId) {
        logger.info("Validating TOTP code for user: {} in service: {}", userId, serviceId);

        TotpSecret totpSecret = repository.findByUserIdAndServiceId(userId, serviceId)
                .orElseThrow(() -> new SecretNotFoundException(
                        "No 2FA configuration found for user: " + userId
                ));

        if (!totpSecret.getEnabled()) {
            throw new GoogleAuthenticatorException("2FA is not enabled for this user");
        }

        // Check if account is locked
        if (totpSecret.isLocked()) {
            logger.warn("Account locked for user: {} until: {}", userId, totpSecret.getLockedUntil());
            throw new AccountLockedException(
                    "Account is locked due to too many failed attempts. Please try again later.",
                    totpSecret.getLockedUntil()
            );
        }

        // Decrypt secret
        String secretKey = encryptionUtil.decrypt(totpSecret.getEncryptedSecret());

        // Parse code
        int codeInt;
        try {
            codeInt = Integer.parseInt(code);
        } catch (NumberFormatException e) {
            return handleFailedValidation(totpSecret, "Invalid code format");
        }

        // Validate code
        boolean isValid = googleAuthenticator.authorize(secretKey, codeInt);

        if (isValid) {
            // Reset failed attempts on successful validation
            totpSecret.resetFailedAttempts();
            totpSecret.setLastValidatedAt(LocalDateTime.now());
            repository.save(totpSecret);

            logger.info("Successfully validated TOTP code for user: {}", userId);

            return ValidationResponse.builder()
                    .valid(true)
                    .message("Code validated successfully")
                    .failedAttempts(0)
                    .maxFailedAttempts(config.getMaxFailedAttempts())
                    .locked(false)
                    .build();
        } else {
            return handleFailedValidation(totpSecret, "Invalid code");
        }
    }

    /**
     * Validate a backup code
     *
     * @param userId User identifier
     * @param backupCode Backup code to validate
     * @param serviceId Service identifier
     * @return ValidationResponse with validation result
     */
    @Transactional
    public ValidationResponse validateBackupCode(String userId, String backupCode, String serviceId) {
        logger.info("Validating backup code for user: {} in service: {}", userId, serviceId);

        TotpSecret totpSecret = repository.findByUserIdAndServiceId(userId, serviceId)
                .orElseThrow(() -> new SecretNotFoundException(
                        "No 2FA configuration found for user: " + userId
                ));

        if (totpSecret.getBackupCodes() == null) {
            return ValidationResponse.builder()
                    .valid(false)
                    .message("No backup codes available")
                    .build();
        }

        // Decrypt and check backup codes
        String decryptedCodes = encryptionUtil.decrypt(totpSecret.getBackupCodes());
        List<String> codes = new ArrayList<>(List.of(decryptedCodes.split(",")));

        if (codes.contains(backupCode)) {
            // Remove used backup code
            codes.remove(backupCode);
            String updatedCodes = String.join(",", codes);
            totpSecret.setBackupCodes(encryptionUtil.encrypt(updatedCodes));
            totpSecret.resetFailedAttempts();
            totpSecret.setLastValidatedAt(LocalDateTime.now());
            repository.save(totpSecret);

            logger.info("Successfully validated backup code for user: {}", userId);

            return ValidationResponse.builder()
                    .valid(true)
                    .message("Backup code validated successfully. This code cannot be used again.")
                    .locked(false)
                    .build();
        }

        return handleFailedValidation(totpSecret, "Invalid backup code");
    }

    /**
     * Disable 2FA for a user
     *
     * @param userId User identifier
     * @param serviceId Service identifier
     */
    @Transactional
    public void disable2FA(String userId, String serviceId) {
        logger.info("Disabling 2FA for user: {} in service: {}", userId, serviceId);

        TotpSecret totpSecret = repository.findByUserIdAndServiceId(userId, serviceId)
                .orElseThrow(() -> new SecretNotFoundException(
                        "No 2FA configuration found for user: " + userId
                ));

        totpSecret.setEnabled(false);
        repository.save(totpSecret);

        logger.info("Successfully disabled 2FA for user: {}", userId);
    }

    /**
     * Delete 2FA configuration for a user
     *
     * @param userId User identifier
     * @param serviceId Service identifier
     */
    @Transactional
    public void delete2FA(String userId, String serviceId) {
        logger.info("Deleting 2FA for user: {} in service: {}", userId, serviceId);

        repository.deleteByUserIdAndServiceId(userId, serviceId);

        logger.info("Successfully deleted 2FA for user: {}", userId);
    }

    /**
     * Check if user has 2FA enabled
     *
     * @param userId User identifier
     * @param serviceId Service identifier
     * @return true if 2FA is enabled
     */
    public boolean is2FAEnabled(String userId, String serviceId) {
        return repository.existsByUserIdAndServiceIdAndEnabled(userId, serviceId);
    }

    /**
     * Reset failed attempts for a user (admin function)
     *
     * @param userId User identifier
     * @param serviceId Service identifier
     */
    @Transactional
    public void resetFailedAttempts(String userId, String serviceId) {
        logger.info("Resetting failed attempts for user: {} in service: {}", userId, serviceId);

        TotpSecret totpSecret = repository.findByUserIdAndServiceId(userId, serviceId)
                .orElseThrow(() -> new SecretNotFoundException(
                        "No 2FA configuration found for user: " + userId
                ));

        totpSecret.resetFailedAttempts();
        repository.save(totpSecret);

        logger.info("Successfully reset failed attempts for user: {}", userId);
    }

    /**
     * Generate new backup codes for a user
     *
     * @param userId User identifier
     * @param serviceId Service identifier
     * @return List of new backup codes
     */
    @Transactional
    public List<String> generateNewBackupCodes(String userId, String serviceId) {
        logger.info("Generating new backup codes for user: {} in service: {}", userId, serviceId);

        TotpSecret totpSecret = repository.findByUserIdAndServiceId(userId, serviceId)
                .orElseThrow(() -> new SecretNotFoundException(
                        "No 2FA configuration found for user: " + userId
                ));

        List<String> backupCodes = generateBackupCodes(8);
        String encryptedBackupCodes = encryptionUtil.encrypt(String.join(",", backupCodes));

        totpSecret.setBackupCodes(encryptedBackupCodes);
        repository.save(totpSecret);

        logger.info("Successfully generated new backup codes for user: {}", userId);

        return backupCodes;
    }

    // Private helper methods

    private ValidationResponse handleFailedValidation(TotpSecret totpSecret, String message) {
        totpSecret.incrementFailedAttempts();

        boolean shouldLock = totpSecret.getFailedAttempts() >= config.getMaxFailedAttempts();

        if (shouldLock) {
            LocalDateTime lockUntil = LocalDateTime.now().plusMinutes(config.getLockoutDurationMinutes());
            totpSecret.lockUntil(lockUntil);
            repository.save(totpSecret);

            logger.warn("Account locked for user due to failed attempts. Locked until: {}", lockUntil);

            return ValidationResponse.builder()
                    .valid(false)
                    .message("Too many failed attempts. Account locked.")
                    .failedAttempts(totpSecret.getFailedAttempts())
                    .maxFailedAttempts(config.getMaxFailedAttempts())
                    .locked(true)
                    .lockedUntil(lockUntil.toString())
                    .build();
        }

        repository.save(totpSecret);

        return ValidationResponse.builder()
                .valid(false)
                .message(message)
                .failedAttempts(totpSecret.getFailedAttempts())
                .maxFailedAttempts(config.getMaxFailedAttempts())
                .locked(false)
                .build();
    }

    private List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            // Generate 8-character alphanumeric backup codes
            String code = generateRandomCode(8);
            codes.add(code);
        }
        return codes;
    }

    private String generateRandomCode(int length) {
        String characters = ALPHA_NUMERIC;
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int index = secureRandom.nextInt(characters.length());
            code.append(characters.charAt(index));
        }
        return code.toString();
    }
}
