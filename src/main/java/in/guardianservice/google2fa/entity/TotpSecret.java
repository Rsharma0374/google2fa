package in.guardianservice.google2fa.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity representing a user's TOTP secret configuration
 */
@Entity
@Table(name = "totp_secrets",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "service_id"}),
        indexes = {
                @Index(name = "idx_user_service", columnList = "user_id,service_id"),
                @Index(name = "idx_service_id", columnList = "service_id")
        })
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TotpSecret {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * User identifier from the calling service
     */
    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    /**
     * Service identifier to support multi-tenancy
     */
    @Column(name = "service_id", nullable = false, length = 100)
    private String serviceId;

    /**
     * Encrypted secret key for TOTP generation
     */
    @Column(name = "encrypted_secret", nullable = false, length = 500)
    private String encryptedSecret;

    /**
     * Whether 2FA is enabled for this user
     */
    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    /**
     * Timestamp when the secret was created
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * Timestamp of the last successful validation
     */
    @Column(name = "last_validated_at")
    private LocalDateTime lastValidatedAt;

    /**
     * Counter for failed validation attempts
     */
    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private Integer failedAttempts = 0;

    /**
     * Timestamp when the account was locked due to failed attempts
     */
    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    /**
     * Last updated timestamp
     */
    @Column(name = "updated_at")
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    /**
     * Backup codes for account recovery (encrypted, comma-separated)
     */
    @Column(name = "backup_codes", length = 1000)
    private String backupCodes;

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
        if (this.updatedAt == null) {
            this.updatedAt = LocalDateTime.now();
        }
        if (this.enabled == null) {
            this.enabled = true;
        }
        if (this.failedAttempts == null) {
            this.failedAttempts = 0;
        }
    }

    /**
     * Check if the account is currently locked
     */
    public boolean isLocked() {
        return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
    }

    /**
     * Increment failed attempts counter
     */
    public void incrementFailedAttempts() {
        this.failedAttempts++;
    }

    /**
     * Reset failed attempts counter
     */
    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.lockedUntil = null;
    }

    /**
     * Lock the account until the specified time
     */
    public void lockUntil(LocalDateTime until) {
        this.lockedUntil = until;
    }
}
