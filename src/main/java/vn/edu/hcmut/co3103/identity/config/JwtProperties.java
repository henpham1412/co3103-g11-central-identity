package vn.edu.hcmut.co3103.identity.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /** Base64-encoded HMAC signing key containing at least 32 random bytes. */
    @NotBlank
    private String secret;

    @Positive
    private long expirationMs = 86400000L;

    @Positive
    private long refreshExpirationMs = 604800000L;
}
