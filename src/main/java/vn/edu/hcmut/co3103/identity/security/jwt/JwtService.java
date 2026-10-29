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
        if (subject == null || !UUID.fromString(subject).toString().equalsIgnoreCase(subject)) {
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
        return extractClaim(token, this::emailFromClaims);
    }

    private String emailFromClaims(Claims claims) {
        String email = claims.get("email", String.class);
        String subject = claims.getSubject();
        return email == null && subject != null && subject.contains("@") ? subject : email;
    }

    public String extractUserId(String token) {
        return extractClaim(token, claims -> {
            String subject = claims.getSubject();
            return StringUtils.hasText(subject) && !subject.contains("@")
                    ? subject : claims.get("userId", String.class);
        });
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
            return StringUtils.hasText(claims.getSubject())
                    && claims.getExpiration() != null
                    && claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = extractAllClaims(token);
            return StringUtils.hasText(claims.getSubject())
                    && userDetails.getUsername().equals(emailFromClaims(claims))
                    && claims.getExpiration() != null
                    && claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    /** Returns true for expired or non-expiring tokens; rejects other invalid JWTs. */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = extractClaim(token, Claims::getExpiration);
            return expiration == null || !expiration.after(new Date());
        } catch (ExpiredJwtException exception) {
            return true;
        }
    }

    private Claims extractAllClaims(String token) {
        return jwtParser.parseSignedClaims(token).getPayload();
    }
}
