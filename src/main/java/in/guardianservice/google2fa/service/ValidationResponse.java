package in.guardianservice.google2fa.service;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for code validation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ValidationResponse {


    /**
     * Whether the code was valid
     */
    private boolean valid;

    /**
     * Message describing the validation result
     */
    private String message;

    /**
     * Number of failed attempts (if validation failed)
     */
    private Integer failedAttempts;

    /**
     * Maximum allowed failed attempts
     */
    private Integer maxFailedAttempts;

    /**
     * Whether the account is locked
     */
    private boolean locked;

    /**
     * ISO-8601 timestamp when the lock expires (if locked)
     */
    private String lockedUntil;
}
