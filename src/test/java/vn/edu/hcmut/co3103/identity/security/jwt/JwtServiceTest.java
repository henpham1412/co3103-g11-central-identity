package vn.edu.hcmut.co3103.identity.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.userdetails.UserDetails;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.entity.User;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String SECRET = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final String EMAIL = "student@example.com";
    private static final String CLIENT_ID = "lms-client";

    private JwtProperties properties;
    private JwtService jwtService;
    private SecretKey signingKey;
    private User user;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        properties = new JwtProperties();
        properties.setSecret(SECRET);
        jwtService = new JwtService(properties);
        signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));
        user = User.builder()
                .userId(UUID.fromString("3c6d9c41-950b-45f9-a4be-5286ba845e77"))
                .email(EMAIL)
                .fullName("Test Student")
                .passwordHash("unused-password-hash")
                .build();
        userDetails = org.springframework.security.core.userdetails.User.withUsername(EMAIL)
                .password("unused-password-hash")
                .authorities("READ_PROFILE")
                .build();
    }

    @Test
    void defaultsToOneDayAccessAndSevenDayRefreshExpiration() {
        assertEquals(86400000L, properties.getExpirationMs());
        assertEquals(604800000L, properties.getRefreshExpirationMs());
    }

    @Test
    void generatesSignedTokenWithIdentityClaimsAndLifetime() {
        long beforeGeneration = System.currentTimeMillis();
        String token = jwtService.generateToken(user, CLIENT_ID);
        Claims claims = Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();

        assertAll(
                () -> assertEquals(3, token.split("\\.").length),
                () -> assertEquals(EMAIL, claims.getSubject()),
                () -> assertEquals(user.getUserId().toString(), claims.get("userId", String.class)),
                () -> assertEquals(user.getFullName(), claims.get("fullName", String.class)),
                () -> assertEquals(CLIENT_ID, claims.get("clientId", String.class)),
                () -> assertTrue(claims.getIssuedAt().getTime() >= beforeGeneration - 999),
                () -> assertTrue(claims.getIssuedAt().getTime() <= System.currentTimeMillis()),
                () -> assertEquals(properties.getExpirationMs(),
                        claims.getExpiration().getTime() - claims.getIssuedAt().getTime()),
                () -> assertFalse(claims.containsKey("passwordHash"))
        );
    }

    @Test
    void generatesTokenFromUserWithoutClientId() {
        String token = jwtService.generateToken(user);

        assertTrue(jwtService.isTokenValid(token, userDetails));
        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, claims -> claims.get("userId")));
        assertEquals(user.getFullName(), jwtService.extractClaim(token, claims -> claims.get("fullName")));
        assertNull(jwtService.extractClaim(token, claims -> claims.get("clientId")));
    }

    @Test
    void generatesTokenWhenOptionalClientIdIsAbsent() {
        String token = jwtService.generateToken(user, null);

        assertTrue(jwtService.isTokenValid(token, userDetails));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, claims -> claims.get("userId")));
        assertNull(jwtService.extractClaim(token, claims -> claims.get("clientId")));
    }

    @Test
    void generatesTokenFromUserDetailsWithCustomClaims() {
        String token = jwtService.generateToken(Map.of(
                "userId", user.getUserId().toString(), "fullName", user.getFullName(), "clientId", CLIENT_ID),
                userDetails);

        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, claims -> claims.get("userId")));
        assertEquals(user.getFullName(), jwtService.extractClaim(token, claims -> claims.get("fullName")));
        assertEquals(CLIENT_ID, jwtService.extractClaim(token, claims -> claims.get("clientId")));
    }

    @Test
    void usesConfiguredLifetimeAndPreventsCustomClaimsOverridingSubjectOrDates() {
        properties.setExpirationMs(300000L);
        String token = jwtService.generateToken(Map.of(
                "sub", "other@example.com", "iat", new Date(0), "exp", new Date(0)), userDetails);

        Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);
        Date expiration = jwtService.extractClaim(token, Claims::getExpiration);
        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertTrue(issuedAt.after(new Date(0)));
        assertEquals(300000L, expiration.getTime() - issuedAt.getTime());
        assertTrue(jwtService.isTokenValid(token));
    }

    @Test
    void extractsEmailUsernameAndTypedClaims() {
        String token = jwtService.generateToken(user, CLIENT_ID);

        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(EMAIL, jwtService.extractUsername(token));
        assertEquals(CLIENT_ID, jwtService.extractClaim(token, claims -> claims.get("clientId", String.class)));
        assertNotNull(jwtService.extractClaim(token, Claims::getExpiration));
    }

    @Test
    void validatesTokenForMatchingUser() {
        String token = jwtService.generateToken(userDetails);

        assertTrue(jwtService.isTokenValid(token));
        assertTrue(jwtService.isTokenValid(token, userDetails));
        assertFalse(jwtService.isTokenExpired(token));
    }

    @Test
    void rejectsTokenForDifferentUser() {
        UserDetails otherUser = org.springframework.security.core.userdetails.User
                .withUserDetails(userDetails).username("other@example.com").build();

        assertFalse(jwtService.isTokenValid(jwtService.generateToken(userDetails), otherUser));
    }

    @Test
    void rejectsExpiredTokenAndReportsExpirationWithoutSleeping() {
        String token = Jwts.builder()
                .subject(EMAIL)
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(signingKey)
                .compact();

        assertTrue(jwtService.isTokenExpired(token));
        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, userDetails));
        assertThrows(ExpiredJwtException.class, () -> jwtService.extractEmail(token));
    }

    @Test
    void rejectsTamperedPayload() {
        String[] parts = jwtService.generateToken(userDetails).split("\\.");
        String payload = new String(Decoders.BASE64URL.decode(parts[1]), StandardCharsets.UTF_8)
                .replace(EMAIL, "attacker@example.com");
        String tamperedToken = parts[0] + "."
                + Encoders.BASE64URL.encode(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];

        assertFalse(jwtService.isTokenValid(tamperedToken));
        assertFalse(jwtService.isTokenValid(tamperedToken, userDetails));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(tamperedToken));
        assertThrows(JwtException.class, () -> jwtService.isTokenExpired(tamperedToken));
    }

    @Test
    void rejectsTamperedSignature() {
        String[] parts = jwtService.generateToken(userDetails).split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        String tamperedToken = String.join(".", parts);

        assertFalse(jwtService.isTokenValid(tamperedToken));
        assertThrows(JwtException.class, () -> jwtService.extractClaim(tamperedToken, Claims::getSubject));
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        String token = Jwts.builder()
                .subject(EMAIL)
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(Jwts.SIG.HS256.key().build())
                .compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, userDetails));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(token));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "not-a-jwt", "abc.def.ghi"})
    void rejectsMalformedOrMissingTokens(String token) {
        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, userDetails));
    }

    @Test
    void rejectsUnsignedToken() {
        String token = Jwts.builder().subject(EMAIL)
                .expiration(Date.from(Instant.now().plusSeconds(60))).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(token));
    }

    @Test
    void rejectsTokenWithoutExpiration() {
        String token = Jwts.builder().subject(EMAIL).signWith(signingKey).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, userDetails));
        assertTrue(jwtService.isTokenExpired(token));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void rejectsTokenWithoutMeaningfulSubject(String subject) {
        String token = Jwts.builder().subject(subject)
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(signingKey).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, userDetails));
    }

    @Test
    void rejectsTokenThatIsNotYetValid() {
        String token = Jwts.builder().subject(EMAIL)
                .notBefore(Date.from(Instant.now().plusSeconds(60)))
                .expiration(Date.from(Instant.now().plusSeconds(120)))
                .signWith(signingKey).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, userDetails));
    }

    @Test
    void rejectsWeakSigningKey() {
        properties.setSecret(Encoders.BASE64.encode("too-short".getBytes(StandardCharsets.UTF_8)));

        assertThrows(WeakKeyException.class, () -> new JwtService(properties));
    }
}
