package in.guardianservice.google2fa.config;

import lombok.Getter;

import javax.sql.DataSource;
import java.util.Objects;

/**
 * Configuration class for Google Authenticator Service
 * This class holds all configuration parameters needed by the service
 */
@Getter
public class GoogleAuthenticatorConfig {

    private final DataSource dataSource;
    private final String encryptionKey;
    private final int timeWindow;
    private final int codeDigits;
    private final int secretLength;
    private final String issuerName;
    private final int maxFailedAttempts;
    private final long lockoutDurationMinutes;
    private final String tablePrefix;

    private GoogleAuthenticatorConfig(Builder builder) {
        this.dataSource = Objects.requireNonNull(builder.dataSource, "DataSource cannot be null");
        this.encryptionKey = Objects.requireNonNull(builder.encryptionKey, "Encryption key cannot be null");
        this.timeWindow = builder.timeWindow;
        this.codeDigits = builder.codeDigits;
        this.secretLength = builder.secretLength;
        this.issuerName = builder.issuerName;
        this.maxFailedAttempts = builder.maxFailedAttempts;
        this.lockoutDurationMinutes = builder.lockoutDurationMinutes;
        this.tablePrefix = builder.tablePrefix;

        validateConfig();
    }

    private void validateConfig() {
        if (encryptionKey.length() < 16) {
            throw new IllegalArgumentException("Encryption key must be at least 16 characters");
        }
        if (timeWindow < 0 || timeWindow > 5) {
            throw new IllegalArgumentException("Time window must be between 0 and 5");
        }
        if (codeDigits < 6 || codeDigits > 8) {
            throw new IllegalArgumentException("Code digits must be between 6 and 8");
        }
    }

    /**
     * Builder class for GoogleAuthenticatorConfig
     */
    public static class Builder {
        private DataSource dataSource;
        private String encryptionKey;
        private int timeWindow = 1; // Allow codes from ±1 time window (30 seconds before/after)
        private int codeDigits = 6; // Standard 6-digit codes
        private int secretLength = 20; // Length of the secret key
        private String issuerName = "MyApp";
        private int maxFailedAttempts = 5;
        private long lockoutDurationMinutes = 15;
        private String tablePrefix = "";

        /**
         * Set the datasource (Required)
         * @param dataSource JDBC DataSource
         * @return Builder instance
         */
        public Builder dataSource(DataSource dataSource) {
            this.dataSource = dataSource;
            return this;
        }

        /**
         * Set the encryption key for encrypting secrets at rest (Required)
         * Must be at least 16 characters
         * @param encryptionKey Encryption key
         * @return Builder instance
         */
        public Builder encryptionKey(String encryptionKey) {
            this.encryptionKey = encryptionKey;
            return this;
        }

        /**
         * Set the time window for TOTP validation
         * Default is 1 (accepts codes from ±30 seconds)
         * @param timeWindow Time window (0-5)
         * @return Builder instance
         */
        public Builder timeWindow(int timeWindow) {
            this.timeWindow = timeWindow;
            return this;
        }

        /**
         * Set the number of digits in TOTP code
         * Default is 6
         * @param codeDigits Number of digits (6-8)
         * @return Builder instance
         */
        public Builder codeDigits(int codeDigits) {
            this.codeDigits = codeDigits;
            return this;
        }

        /**
         * Set the length of the secret key
         * Default is 20
         * @param secretLength Secret length
         * @return Builder instance
         */
        public Builder secretLength(int secretLength) {
            this.secretLength = secretLength;
            return this;
        }

        /**
         * Set the issuer name for QR codes
         * Default is "MyApp"
         * @param issuerName Issuer name
         * @return Builder instance
         */
        public Builder issuerName(String issuerName) {
            this.issuerName = issuerName;
            return this;
        }

        /**
         * Set maximum failed attempts before lockout
         * Default is 5
         * @param maxFailedAttempts Maximum failed attempts
         * @return Builder instance
         */
        public Builder maxFailedAttempts(int maxFailedAttempts) {
            this.maxFailedAttempts = maxFailedAttempts;
            return this;
        }

        /**
         * Set lockout duration in minutes after max failed attempts
         * Default is 15 minutes
         * @param lockoutDurationMinutes Lockout duration
         * @return Builder instance
         */
        public Builder lockoutDurationMinutes(long lockoutDurationMinutes) {
            this.lockoutDurationMinutes = lockoutDurationMinutes;
            return this;
        }

        /**
         * Set table prefix for database tables
         * Default is empty string
         * @param tablePrefix Table prefix
         * @return Builder instance
         */
        public Builder tablePrefix(String tablePrefix) {
            this.tablePrefix = tablePrefix;
            return this;
        }

        /**
         * Build the GoogleAuthenticatorConfig instance
         * @return GoogleAuthenticatorConfig instance
         */
        public GoogleAuthenticatorConfig build() {
            return new GoogleAuthenticatorConfig(this);
        }
    }
}
