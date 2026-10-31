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

    /** Issuer shared with services that verify this application's access tokens. */
    @NotBlank
    private String issuer = "http://localhost:8080";

    /** PKCS#8 PEM private key; configure together with the public key. */
    private String privateKey;

    /** X.509 PEM public key. */
    private String publicKey;

    /** Explicit opt-in for local development and tests; deployments require persistent keys. */
    private boolean allowEphemeralKeys;

    @Positive
    private long expirationMs = 86400000L;

    @Positive
    private long refreshExpirationMs = 604800000L;
}
