package in.guardianservice.google2fa.util;


import in.guardianservice.google2fa.exception.GoogleAuthenticatorException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Utility class for encrypting and decrypting TOTP secrets
 * Uses AES-256-CBC encryption
 */
public class EncryptionUtil {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final int IV_LENGTH = 16;

    private final SecretKey secretKey;
    private final SecureRandom secureRandom;

    public EncryptionUtil(String encryptionKey) {
        try {
            this.secretKey = generateKey(encryptionKey);
            this.secureRandom = new SecureRandom();
        } catch (Exception e) {
            throw new GoogleAuthenticatorException("Failed to initialize encryption", e);
        }
    }

    /**
     * Generate AES key from password using PBKDF2
     */
    private SecretKey generateKey(String password) throws Exception {
        byte[] salt = "GoogleAuth2FA".getBytes(); // Fixed salt for deterministic key generation
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    /**
     * Encrypt a string value
     * @param value Plain text to encrypt
     * @return Base64 encoded encrypted string with IV prepended
     */
    public String encrypt(String value) {
        try {
            // Generate random IV
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Encrypt
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encrypted = cipher.doFinal(value.getBytes());

            // Combine IV and encrypted data
            byte[] combined = new byte[IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, IV_LENGTH);
            System.arraycopy(encrypted, 0, combined, IV_LENGTH, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new GoogleAuthenticatorException("Encryption failed", e);
        }
    }

    /**
     * Decrypt an encrypted string
     * @param encryptedValue Base64 encoded encrypted string with IV prepended
     * @return Decrypted plain text
     */
    public String decrypt(String encryptedValue) {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedValue);

            // Extract IV
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Extract encrypted data
            byte[] encrypted = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, IV_LENGTH, encrypted, 0, encrypted.length);

            // Decrypt
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted);
        } catch (Exception e) {
            throw new GoogleAuthenticatorException("Decryption failed", e);
        }
    }
}
