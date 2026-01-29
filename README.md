# Google Authenticator Service - JAR Library

A standalone Google Authenticator/TOTP (Time-based One-Time Password) service that can be integrated as a JAR dependency into any Java/Spring Boot application.

## Features

- ✅ Generate TOTP secrets for users
- ✅ Validate TOTP codes
- ✅ Generate QR codes for Google Authenticator app
- ✅ Backup codes for account recovery
- ✅ Account lockout after failed attempts
- ✅ Multi-tenancy support (multiple services can use the same instance)
- ✅ AES-256 encryption for secrets at rest
- ✅ PostgreSQL support with automatic migrations
- ✅ Configurable time windows, code digits, and security parameters

## Requirements

- Java 17 or higher
- Spring Boot 3.x
- PostgreSQL database
- Maven

## Installation

### 1. Add to your project's `pom.xml`:

```xml
<dependency>
    <groupId>com.auth</groupId>
    <artifactId>google-auth-service</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. Configure your database in `application.yml`:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/your_database
    username: your_username
    password: your_password
  jpa:
    hibernate:
      ddl-auto: update
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
  flyway:
    enabled: true
    locations: classpath:db/migration
```

## Configuration

### Programmatic Configuration (Recommended)

Create a configuration bean in your application:

```java
import com.auth.google.config.GoogleAuthenticatorConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import javax.sql.DataSource;

@Configuration
public class AppConfig {
    
    @Bean
    public GoogleAuthenticatorConfig googleAuthConfig(DataSource dataSource) {
        return new GoogleAuthenticatorConfig.Builder()
            .dataSource(dataSource)
            .encryptionKey("your-secure-encryption-key-min-16-chars")
            .issuerName("MyApp")
            .timeWindow(1)           // ±30 seconds tolerance
            .codeDigits(6)            // 6-digit codes
            .maxFailedAttempts(5)     // Lock after 5 failed attempts
            .lockoutDurationMinutes(15) // Lock for 15 minutes
            .build();
    }
}
```

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `dataSource` | **Required** | JDBC DataSource |
| `encryptionKey` | **Required** | AES encryption key (min 16 chars) |
| `issuerName` | "MyApp" | Name shown in authenticator apps |
| `timeWindow` | 1 | Time tolerance (±30 seconds per unit) |
| `codeDigits` | 6 | Number of digits in TOTP code (6-8) |
| `secretLength` | 20 | Length of generated secrets |
| `maxFailedAttempts` | 5 | Failed attempts before lockout |
| `lockoutDurationMinutes` | 15 | Lockout duration in minutes |
| `tablePrefix` | "" | Database table prefix |

## Usage Examples

### 1. Enable 2FA for a User

```java
import com.auth.google.service.GoogleAuthenticatorService;
import com.auth.google.service.SecretResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    
    @Autowired
    private GoogleAuthenticatorService googleAuthService;
    
    public SecretResponse enable2FA(String userId, String userEmail) {
        // Generate secret and QR code
        SecretResponse response = googleAuthService.generateSecret(
            userId,           // Your user's ID
            "my-app",        // Your service ID
            userEmail        // User's email for QR code label
        );
        
        // Response contains:
        // - secret: Base32 secret (for manual entry)
        // - qrCodeDataUrl: Data URL for QR code image
        // - qrCodeUrl: otpauth:// URL
        // - backupCodes: List of backup codes
        
        // Store backup codes securely or display to user
        System.out.println("Secret: " + response.getSecret());
        System.out.println("Backup codes: " + response.getBackupCodes());
        
        return response;
    }
}
```

### 2. Validate TOTP Code

```java
import com.auth.google.service.ValidationResponse;

@Service
public class AuthService {
    
    @Autowired
    private GoogleAuthenticatorService googleAuthService;
    
    public boolean verifyLogin(String userId, String totpCode) {
        try {
            ValidationResponse response = googleAuthService.validateCode(
                userId,
                totpCode,
                "my-app"
            );
            
            if (response.isValid()) {
                System.out.println("Login successful!");
                return true;
            } else {
                System.out.println("Invalid code. Attempts: " + 
                    response.getFailedAttempts() + "/" + 
                    response.getMaxFailedAttempts());
                return false;
            }
        } catch (AccountLockedException e) {
            System.out.println("Account locked until: " + e.getLockedUntil());
            return false;
        } catch (SecretNotFoundException e) {
            System.out.println("2FA not set up for this user");
            return false;
        }
    }
}
```

### 3. Validate Backup Code

```java
public boolean verifyWithBackupCode(String userId, String backupCode) {
    ValidationResponse response = googleAuthService.validateBackupCode(
        userId,
        backupCode,
        "my-app"
    );
    
    return response.isValid();
}
```

### 4. Check if User Has 2FA Enabled

```java
public boolean check2FAStatus(String userId) {
    return googleAuthService.is2FAEnabled(userId, "my-app");
}
```

### 5. Disable 2FA

```java
public void disable2FA(String userId) {
    googleAuthService.disable2FA(userId, "my-app");
}
```

### 6. Delete 2FA Configuration

```java
public void remove2FA(String userId) {
    googleAuthService.delete2FA(userId, "my-app");
}
```

### 7. Generate New Backup Codes

```java
public List<String> regenerateBackupCodes(String userId) {
    return googleAuthService.generateNewBackupCodes(userId, "my-app");
}
```

### 8. Reset Failed Attempts (Admin)

```java
public void unlockAccount(String userId) {
    googleAuthService.resetFailedAttempts(userId, "my-app");
}
```

## REST API Example

```java
import com.auth.google.service.GoogleAuthenticatorService;
import com.auth.google.service.SecretResponse;
import com.auth.google.service.ValidationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/2fa")
public class TwoFactorAuthController {
    
    @Autowired
    private GoogleAuthenticatorService googleAuthService;
    
    @PostMapping("/enable")
    public ResponseEntity<SecretResponse> enable2FA(
            @RequestParam String userId,
            @RequestParam String email) {
        SecretResponse response = googleAuthService.generateSecret(
            userId, "my-app", email
        );
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validateCode(
            @RequestParam String userId,
            @RequestParam String code) {
        ValidationResponse response = googleAuthService.validateCode(
            userId, code, "my-app"
        );
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/disable")
    public ResponseEntity<Void> disable2FA(@RequestParam String userId) {
        googleAuthService.disable2FA(userId, "my-app");
        return ResponseEntity.ok().build();
    }
    
    @GetMapping("/status")
    public ResponseEntity<Boolean> check2FAStatus(@RequestParam String userId) {
        boolean enabled = googleAuthService.is2FAEnabled(userId, "my-app");
        return ResponseEntity.ok(enabled);
    }
}
```

## QR Code Display in HTML

```html
<div>
    <h3>Scan this QR code with Google Authenticator</h3>
    <img src="${qrCodeDataUrl}" alt="QR Code" />
    <p>Or enter this code manually: ${secret}</p>
</div>
```

## Security Best Practices

1. **Encryption Key**: Use a strong, randomly generated encryption key (minimum 16 characters)
2. **HTTPS**: Always use HTTPS in production
3. **Backup Codes**: Securely display backup codes to users and ensure they save them
4. **Rate Limiting**: Implement rate limiting on validation endpoints
5. **Audit Logging**: Log all 2FA operations for security auditing
6. **Time Sync**: Ensure server time is synchronized using NTP

## Exception Handling

The library throws the following exceptions:

- `GoogleAuthenticatorException`: Base exception for all errors
- `SecretNotFoundException`: User doesn't have 2FA configured
- `InvalidCodeException`: TOTP code validation failed
- `AccountLockedException`: Account locked due to failed attempts

```java
try {
    ValidationResponse response = googleAuthService.validateCode(userId, code, serviceId);
} catch (AccountLockedException e) {
    // Handle locked account
    LocalDateTime lockedUntil = e.getLockedUntil();
} catch (SecretNotFoundException e) {
    // Handle missing 2FA setup
} catch (GoogleAuthenticatorException e) {
    // Handle other errors
}
```

## Database Schema

The library automatically creates the following table:

```sql
totp_secrets (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255),
    service_id VARCHAR(100),
    encrypted_secret VARCHAR(500),
    enabled BOOLEAN,
    created_at TIMESTAMP,
    last_validated_at TIMESTAMP,
    failed_attempts INTEGER,
    locked_until TIMESTAMP,
    updated_at TIMESTAMP,
    backup_codes VARCHAR(1000),
    UNIQUE(user_id, service_id)
)
```

## Multi-Tenancy

The library supports multiple services using the same database:

```java
// Service A
googleAuthService.generateSecret("user123", "service-a", "user@example.com");

// Service B
googleAuthService.generateSecret("user123", "service-b", "user@example.com");
```

Each service maintains isolated 2FA configurations.

## Testing

Include H2 database for testing:

```xml
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>test</scope>
</dependency>
```

```yaml
# application-test.yml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
```

## License

MIT License

## Support

For issues and questions, please open an issue on the project repository.
