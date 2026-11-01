package vn.edu.hcmut.co3103.identity.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/** Reconstructs retry credentials without persisting bearer tokens or reusing JWT keys. */
@Component
public class RecoveryTokens {
    private final SecretKeySpec key;

    public RecoveryTokens(@Value("${app.recovery.token-key:}") String encodedKey) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(encodedKey);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Recovery token key must be base64 encoded (32 bytes)");
        }
        if (bytes.length != 32) throw new IllegalArgumentException("Recovery token key must contain 32 random bytes");
        key = new SecretKeySpec(bytes, "HmacSHA256");
    }

    public String token(UUID requestId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(
                    ("ci-password-recovery-v1:" + requestId).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HmacSHA256 is required by the Java runtime");
        }
    }

    public static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime");
        }
    }
}
