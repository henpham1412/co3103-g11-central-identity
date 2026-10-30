package vn.edu.hcmut.co3103.identity.security.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.test.context.DynamicPropertyRegistry;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;

import java.security.Key;
import java.security.KeyPair;
import java.util.Base64;

/** Ephemeral keys shared by tests; no signing credentials are stored in the repository. */
public final class JwtTestKeys {

    public static final KeyPair KEY_PAIR = Jwts.SIG.RS256.keyPair().build();

    private JwtTestKeys() {
    }

    public static String pem(Key key, String type) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
                + "\n-----END " + type + "-----";
    }

    public static JwtProperties properties() {
        JwtProperties properties = new JwtProperties();
        properties.setPrivateKey(pem(KEY_PAIR.getPrivate(), "PRIVATE KEY"));
        properties.setPublicKey(pem(KEY_PAIR.getPublic(), "PUBLIC KEY"));
        return properties;
    }

    public static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.private-key", () -> pem(KEY_PAIR.getPrivate(), "PRIVATE KEY"));
        registry.add("jwt.public-key", () -> pem(KEY_PAIR.getPublic(), "PUBLIC KEY"));
    }
}
