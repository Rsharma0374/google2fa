package in.guardianservice.google2fa.repository;

import in.guardianservice.google2fa.entity.TotpSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for TotpSecret entity
 */
@Repository
public interface TotpSecretRepository extends JpaRepository<TotpSecret, Long> {

    /**
     * Find a TOTP secret by user ID and service ID
     * @param userId User identifier
     * @param serviceId Service identifier
     * @return Optional TotpSecret
     */
    Optional<TotpSecret> findByUserIdAndServiceId(String userId, String serviceId);

    /**
     * Find all TOTP secrets for a service
     * @param serviceId Service identifier
     * @return List of TotpSecrets
     */
    List<TotpSecret> findByServiceId(String serviceId);

    /**
     * Check if a user has 2FA enabled
     * @param userId User identifier
     * @param serviceId Service identifier
     * @return true if exists and enabled
     */
    @Query("SELECT CASE WHEN COUNT(t) > 0 THEN true ELSE false END " +
            "FROM TotpSecret t WHERE t.userId = :userId AND t.serviceId = :serviceId AND t.enabled = true")
    boolean existsByUserIdAndServiceIdAndEnabled(@Param("userId") String userId,
                                                 @Param("serviceId") String serviceId);

    /**
     * Delete TOTP secret by user ID and service ID
     * @param userId User identifier
     * @param serviceId Service identifier
     */
    @Modifying
    @Query("DELETE FROM TotpSecret t WHERE t.userId = :userId AND t.serviceId = :serviceId")
    void deleteByUserIdAndServiceId(@Param("userId") String userId, @Param("serviceId") String serviceId);

    /**
     * Disable 2FA for a user
     * @param userId User identifier
     * @param serviceId Service identifier
     */
    @Modifying
    @Query("UPDATE TotpSecret t SET t.enabled = false, t.updatedAt = :now " +
            "WHERE t.userId = :userId AND t.serviceId = :serviceId")
    void disableByUserIdAndServiceId(@Param("userId") String userId,
                                     @Param("serviceId") String serviceId,
                                     @Param("now") LocalDateTime now);

    /**
     * Find all locked accounts
     * @return List of locked TotpSecrets
     */
    @Query("SELECT t FROM TotpSecret t WHERE t.lockedUntil IS NOT NULL AND t.lockedUntil > :now")
    List<TotpSecret> findAllLocked(@Param("now") LocalDateTime now);

    /**
     * Count enabled 2FA users for a service
     * @param serviceId Service identifier
     * @return Count of enabled users
     */
    @Query("SELECT COUNT(t) FROM TotpSecret t WHERE t.serviceId = :serviceId AND t.enabled = true")
    long countEnabledByServiceId(@Param("serviceId") String serviceId);
}
