package vn.edu.hcmut.co3103.identity.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    private final JwtProperties jwtProperties;
    private final SecretKey signingKey;
    private final JwtParser jwtParser;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecret()));
        var algorithms = Jwts.parser().verifyWith(signingKey).sig();
        // JJWT 0.12.6 rejects an empty registry, so retain HS256 while removing the others.
        for (var algorithm : Jwts.SIG.get().values()) {
            if (!Jwts.SIG.HS256.getId().equals(algorithm.getId())) {
                algorithms.remove(algorithm);
            }
        }
        this.jwtParser = algorithms.and().build();
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
                .claims(claims)
                .subject(subject)
                .issuedAt(issuedAt)
                .expiration(new Date(issuedAt.getTime() + jwtProperties.getExpirationMs()))
                .signWith(signingKey, Jwts.SIG.HS256)
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
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();
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
