package vn.edu.hcmut.co3103.identity.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    private final JwtProperties jwtProperties;
    private final PrivateKey signingKey;
    private final String issuer;
    private final String keyId;
    private final Map<String, List<Map<String, Object>>> jwks;
    private final JwtParser jwtParser;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        if (!StringUtils.hasText(jwtProperties.getIssuer())) {
            throw new IllegalArgumentException("JWT issuer is required");
        }
        this.issuer = jwtProperties.getIssuer();
        KeyPair keyPair = loadKeyPair(jwtProperties);
        this.signingKey = keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        try {
            RSAKey publicJwk = new RSAKey.Builder(publicKey).keyIDFromThumbprint()
                    .algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).build();
            this.keyId = publicJwk.getKeyID();
            this.jwks = Map.of("keys", List.of(Map.copyOf(publicJwk.toJSONObject())));
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to create JWT public key identifier", exception);
        }
        var algorithms = Jwts.parser().verifyWith(publicKey).requireIssuer(issuer).sig();
        // JJWT 0.12.6 rejects an empty registry, so retain RS256 while removing the others.
        for (var algorithm : Jwts.SIG.get().values()) {
            if (!Jwts.SIG.RS256.getId().equals(algorithm.getId())) {
                algorithms.remove(algorithm);
            }
        }
        this.jwtParser = algorithms.and().build();
    }

    private static KeyPair loadKeyPair(JwtProperties properties) {
        boolean hasPrivateKey = StringUtils.hasText(properties.getPrivateKey());
        boolean hasPublicKey = StringUtils.hasText(properties.getPublicKey());
        if (!hasPrivateKey && !hasPublicKey) {
            return Jwts.SIG.RS256.keyPair().build();
        }
        if (!hasPrivateKey || !hasPublicKey) {
            throw new IllegalArgumentException("Both JWT private and public keys must be configured");
        }
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(decodePem(properties.getPrivateKey(), "PRIVATE KEY")));
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(decodePem(properties.getPublicKey(), "PUBLIC KEY")));
            if (privateKey.getModulus().bitLength() < 2048 || publicKey.getModulus().bitLength() < 2048) {
                throw new IllegalArgumentException("JWT RSA keys must contain at least 2048 bits");
            }
            Signature signature = Signature.getInstance("SHA256withRSA");
            byte[] probe = "jwt-key-pair-check".getBytes(StandardCharsets.US_ASCII);
            signature.initSign(privateKey);
            signature.update(probe);
            byte[] signed = signature.sign();
            signature.initVerify(publicKey);
            signature.update(probe);
            if (!signature.verify(signed)) {
                throw new IllegalArgumentException("JWT private and public keys must match");
            }
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("Invalid JWT RSA key configuration", exception);
        }
    }

    private static byte[] decodePem(String pem, String type) {
        String normalized = pem.replace("\\n", "\n").trim();
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
            throw new IllegalArgumentException("JWT key must use " + type + " PEM encoding");
        }
        return Decoders.BASE64.decode(normalized.substring(begin.length(), normalized.length() - end.length())
                .replaceAll("\\s", ""));
    }

    public Map<String, List<Map<String, Object>>> getJwks() {
        return jwks;
    }

    public String generateToken(User user) {
        return generateToken(user, null);
    }

    public String generateToken(User user, String clientId) {
        Map<String, Object> claims = identityClaims(user, Map.of());
        if (clientId != null) {
            claims.put("clientId", clientId);
        }
        return buildToken(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    public String generateToken(Map<String, Object> claims, UserDetails userDetails) {
        if (userDetails == null || claims == null) {
            throw new IllegalArgumentException("Principal and claims are required");
        }
        if (userDetails instanceof User user) {
            return buildToken(identityClaims(user, claims));
        }
        if (userDetails instanceof IdentityUserDetails identity) {
            Map<String, Object> identityClaims = new HashMap<>(claims);
            identityClaims.put("userId", identity.getUserId());
            identityClaims.put("email", identity.getUsername());
            identityClaims.put("fullName", identity.getFullName());
            identityClaims.put("role", "USER");
            return buildToken(identityClaims);
        }
        // Generic UserDetails has no identity fields: callers must supply userId and fullName.
        Map<String, Object> identity = new HashMap<>(claims);
        identity.put("email", userDetails.getUsername());
        identity.putIfAbsent("role", "USER");
        return buildToken(identity);
    }

    private Map<String, Object> identityClaims(User user, Map<String, Object> extraClaims) {
        if (user == null || user.getUserId() == null) {
            throw new IllegalArgumentException("A User with a UUID userId is required");
        }
        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put("userId", user.getUserId().toString());
        claims.put("email", user.getEmail());
        claims.put("role", "USER");
        claims.put("fullName", user.getFullName());
        return claims;
    }

    private String buildToken(Map<String, Object> claims) {
        Object id = claims.get("userId");
        String subject = id instanceof UUID uuid ? uuid.toString() : id instanceof String text ? text : null;
        if (!isCanonicalUuid(subject)) {
            throw new IllegalArgumentException("A canonical UUID userId is required to issue a token");
        }
        subject = UUID.fromString(subject).toString();
        claims.put("userId", subject);
        for (String name : new String[]{"email", "role", "fullName"}) {
            if (!(claims.get(name) instanceof String value) || !StringUtils.hasText(value)) {
                throw new IllegalArgumentException("Identity claim " + name + " is required to issue a token");
            }
        }
        Date issuedAt = new Date();
        return Jwts.builder()
                .header().keyId(keyId).and()
                .claims(claims)
                .issuer(issuer)
                .subject(subject)
                .issuedAt(issuedAt)
                .expiration(new Date(issuedAt.getTime() + jwtProperties.getExpirationMs()))
                .signWith(signingKey, Jwts.SIG.RS256)
                .compact();
    }

    public String extractEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }

    public String extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", String.class));
    }

    public String extractUsername(String token) {
        return extractEmail(token);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = extractAllClaims(token);
            UUID userId = userDetails instanceof IdentityUserDetails identity ? identity.getUserId()
                    : userDetails instanceof User user ? user.getUserId() : null;
            return userId != null
                    && userId.toString().equals(claims.getSubject())
                    && claims.get("email", String.class).equalsIgnoreCase(userDetails.getUsername())
                    && claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    /** Returns true for expired or non-expiring tokens; rejects other invalid JWTs. */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = jwtParser.parseSignedClaims(token).getPayload().getExpiration();
            return expiration == null || !expiration.after(new Date());
        } catch (ExpiredJwtException exception) {
            return true;
        }
    }

    private Claims extractAllClaims(String token) {
        var signedClaims = jwtParser.parseSignedClaims(token);
        if (!keyId.equals(signedClaims.getHeader().getKeyId())) {
            throw new JwtException("JWT key identifier is missing or unknown");
        }
        Claims claims = signedClaims.getPayload();
        for (String name : new String[]{"sub", "userId", "email", "role", "fullName"}) {
            if (!(claims.get(name) instanceof String value) || !StringUtils.hasText(value)) {
                throw new JwtException("Required identity claim is missing or invalid: " + name);
            }
        }
        String subject = claims.getSubject();
        String userId = claims.get("userId", String.class);
        if (!isCanonicalUuid(subject) || !isCanonicalUuid(userId) || !subject.equals(userId)) {
            throw new JwtException("JWT subject and userId must identify the same canonical UUID");
        }
        if (claims.getExpiration() == null) {
            throw new JwtException("JWT expiration is required");
        }
        return claims;
    }

    private static boolean isCanonicalUuid(String value) {
        if (value == null) {
            return false;
        }
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
