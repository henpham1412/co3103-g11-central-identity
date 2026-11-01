package vn.edu.hcmut.co3103.identity.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.userdetails.UserDetails;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String EMAIL = "student@example.com";
    private static final String CLIENT_ID = "lms-client";

    private JwtProperties properties;
    private JwtService jwtService;
    private PrivateKey signingKey;
    private PublicKey publicKey;
    private String keyId;
    private User user;
    private UserDetails userDetails;
    private UserDetails identityDetails;

    @BeforeEach
    void setUp() {
        properties = JwtTestKeys.properties();
        jwtService = new JwtService(properties);
        signingKey = JwtTestKeys.KEY_PAIR.getPrivate();
        publicKey = JwtTestKeys.KEY_PAIR.getPublic();
        keyId = (String) jwtService.getJwks().get("keys").getFirst().get("kid");
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
        identityDetails = new IdentityUserDetails(user);
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
        var signedClaims = Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token);
        Claims claims = signedClaims.getPayload();

        assertAll(
                () -> assertEquals(3, token.split("\\.").length),
                () -> assertEquals("RS256", signedClaims.getHeader().getAlgorithm()),
                () -> assertEquals(keyId, signedClaims.getHeader().getKeyId()),
                () -> assertEquals("http://localhost:8080", claims.getIssuer()),
                () -> assertEquals(user.getUserId().toString(), claims.getSubject()),
                () -> assertEquals(user.getUserId().toString(), claims.get("userId", String.class)),
                () -> assertEquals(EMAIL, claims.get("email", String.class)),
                () -> assertEquals("USER", claims.get("role", String.class)),
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

        assertTrue(jwtService.isTokenValid(token, identityDetails));
        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, claims -> claims.get("userId")));
        assertEquals(user.getFullName(), jwtService.extractClaim(token, claims -> claims.get("fullName")));
        assertEquals("central-identity", jwtService.extractClaim(token, claims -> claims.get("clientId")));
    }

    @Test
    void generatesTokenWhenOptionalClientIdIsAbsent() {
        String token = jwtService.generateToken(user, null);

        assertTrue(jwtService.isTokenValid(token, identityDetails));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, claims -> claims.get("userId")));
        assertEquals("central-identity", jwtService.extractClaim(token, claims -> claims.get("clientId")));
    }

    @Test
    void generatesTokenFromUserDetailsWithCustomClaims() {
        String token = jwtService.generateToken(Map.of(
                "userId", user.getUserId().toString(), "fullName", user.getFullName(), "clientId", CLIENT_ID),
                userDetails);

        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(EMAIL, jwtService.extractClaim(token, claims -> claims.get("email", String.class)));
        assertEquals("USER", jwtService.extractClaim(token, claims -> claims.get("role", String.class)));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, Claims::getSubject));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, claims -> claims.get("userId")));
        assertEquals(user.getFullName(), jwtService.extractClaim(token, claims -> claims.get("fullName")));
        assertEquals(CLIENT_ID, jwtService.extractClaim(token, claims -> claims.get("clientId")));
    }

    @Test
    void userBackedPrincipalKeepsAuthoritativeIdentityAcrossBothOverloads() {
        Map<String, Object> overrides = Map.of("userId", UUID.randomUUID().toString(),
                "email", "attacker@example.com", "fullName", "Other Name", "role", "ADMIN", "clientId", CLIENT_ID);
        for (String token : new String[]{jwtService.generateToken(identityDetails),
                jwtService.generateToken(overrides, identityDetails)}) {
            Claims claims = jwtService.extractClaim(token, value -> value);
            assertEquals(user.getUserId().toString(), claims.getSubject());
            assertEquals(claims.getSubject(), claims.get("userId"));
            assertEquals(EMAIL, claims.get("email"));
            assertEquals(user.getFullName(), claims.get("fullName"));
            assertEquals("USER", claims.get("role"));
        }
        assertEquals(CLIENT_ID, jwtService.extractClaim(jwtService.generateToken(overrides, identityDetails),
                claims -> claims.get("clientId")));
    }

    @Test
    void rejectsGenericPrincipalWithoutIdentityInsteadOfUsingEmailSubject() {
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(userDetails));
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(Map.of(), userDetails));
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(
                Map.of("userId", user.getUserId().toString()), userDetails));
    }

    @ParameterizedTest
    @MethodSource("invalidUserIds")
    void rejectsInvalidUserIdClaims(Object userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("fullName", user.getFullName());
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(claims, userDetails));
    }

    static Stream<Object> invalidUserIds() {
        return Stream.of(null, "", " ", EMAIL, "not-a-uuid", "1-1-1-1-1", 123,
                "00000000-0000-0000-0000-000000000000 ");
    }

    @Test
    void acceptsUuidValueAndDoesNotMutateCallerClaims() {
        Map<String, Object> claims = Map.of("userId", user.getUserId(), "fullName", user.getFullName());
        String token = jwtService.generateToken(claims, userDetails);
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, Claims::getSubject));
        assertEquals(user.getUserId().toString(), jwtService.extractUserId(token));
        assertEquals(user.getUserId(), claims.get("userId"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"email", "role", "fullName"})
    void rejectsBlankOrNonStringIdentityClaims(String name) {
        for (Object invalid : new Object[]{null, "", " ", 123}) {
            Map<String, Object> claims = new HashMap<>(Map.of(
                    "userId", user.getUserId(), "fullName", user.getFullName()));
            UserDetails principal = userDetails;
            if (name.equals("email")) {
                principal = org.mockito.Mockito.mock(UserDetails.class);
                org.mockito.Mockito.when(principal.getUsername()).thenReturn(invalid instanceof String s ? s : null);
            } else {
                claims.put(name, invalid);
            }
            // A null role uses the documented USER default; other empty or malformed claims must fail closed.
            if (name.equals("role") && invalid == null) {
                continue;
            }
            UserDetails tokenPrincipal = principal;
            assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(claims, tokenPrincipal));
        }
    }

    @Test
    void rejectsUserWithoutPersistedIdOrFullName() {
        user.setUserId(null);
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(user));
        identityDetails = new IdentityUserDetails(user);
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(identityDetails));
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(
                Map.of("userId", UUID.randomUUID().toString()), identityDetails));
        user.setUserId(UUID.randomUUID());
        user.setFullName(null);
        assertThrows(IllegalArgumentException.class, () -> jwtService.generateToken(user));
    }

    @Test
    void usesConfiguredLifetimeAndPreventsCustomClaimsOverridingSubjectOrDates() {
        properties.setExpirationMs(300000L);
        String token = jwtService.generateToken(Map.of(
                "sub", "other@example.com", "iat", new Date(0), "exp", new Date(0),
                "iss", "https://untrusted.example"), identityDetails);

        Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);
        Date expiration = jwtService.extractClaim(token, Claims::getExpiration);
        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(user.getUserId().toString(), jwtService.extractClaim(token, Claims::getSubject));
        assertEquals(properties.getIssuer(), jwtService.extractClaim(token, Claims::getIssuer));
        assertTrue(issuedAt.after(new Date(0)));
        assertEquals(300000L, expiration.getTime() - issuedAt.getTime());
        assertTrue(jwtService.isTokenValid(token));
    }

    @Test
    void extractsEmailUsernameAndTypedClaims() {
        String token = jwtService.generateToken(user, CLIENT_ID);

        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(EMAIL, jwtService.extractUsername(token));
        assertEquals(user.getUserId().toString(), jwtService.extractUserId(token));
        assertEquals(CLIENT_ID, jwtService.extractClaim(token, claims -> claims.get("clientId", String.class)));
        assertNotNull(jwtService.extractClaim(token, Claims::getExpiration));
    }

    @Test
    void validatesTokenForMatchingUser() {
        String token = jwtService.generateToken(identityDetails);

        assertTrue(jwtService.isTokenValid(token));
        assertTrue(jwtService.isTokenValid(token, identityDetails));
        assertFalse(jwtService.isTokenExpired(token));
    }

    @Test
    void rejectsTokenForDifferentUser() {
        UserDetails otherUser = org.springframework.security.core.userdetails.User
                .withUserDetails(userDetails).username("other@example.com").build();

        assertFalse(jwtService.isTokenValid(jwtService.generateToken(user), otherUser));
        assertFalse(jwtService.isTokenValid(jwtService.generateToken(identityDetails), otherUser));
    }

    @Test
    void rejectsExpiredTokenAndReportsExpirationWithoutSleeping() {
        String token = Jwts.builder().header().keyId(keyId).and().issuer(properties.getIssuer())
                .subject(EMAIL)
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(signingKey, Jwts.SIG.RS256)
                .compact();

        assertTrue(jwtService.isTokenExpired(token));
        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
        assertThrows(ExpiredJwtException.class, () -> jwtService.extractEmail(token));
    }

    @Test
    void rejectsTamperedPayload() {
        String[] parts = jwtService.generateToken(identityDetails).split("\\.");
        String payload = new String(Decoders.BASE64URL.decode(parts[1]), StandardCharsets.UTF_8)
                .replace(EMAIL, "attacker@example.com");
        String tamperedToken = parts[0] + "."
                + Encoders.BASE64URL.encode(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];

        assertFalse(jwtService.isTokenValid(tamperedToken));
        assertFalse(jwtService.isTokenValid(tamperedToken, identityDetails));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(tamperedToken));
        assertThrows(JwtException.class, () -> jwtService.isTokenExpired(tamperedToken));
    }

    @Test
    void rejectsTamperedSignature() {
        String[] parts = jwtService.generateToken(identityDetails).split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        String tamperedToken = String.join(".", parts);

        assertFalse(jwtService.isTokenValid(tamperedToken));
        assertThrows(JwtException.class, () -> jwtService.extractClaim(tamperedToken, Claims::getSubject));
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        String token = Jwts.builder().header().keyId(keyId).and().issuer(properties.getIssuer())
                .subject(EMAIL)
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(Jwts.SIG.RS256.keyPair().build().getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(token));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "not-a-jwt", "abc.def.ghi"})
    void rejectsMalformedOrMissingTokens(String token) {
        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
    }

    @Test
    void rejectsUnsignedToken() {
        String token = Jwts.builder().header().keyId(keyId).and().issuer(properties.getIssuer()).subject(EMAIL)
                .expiration(Date.from(Instant.now().plusSeconds(60))).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(token));
    }

    @Test
    void rejectsTokenWithoutExpiration() {
        String token = Jwts.builder().header().keyId(keyId).and().issuer(properties.getIssuer()).subject(EMAIL).signWith(signingKey, Jwts.SIG.RS256).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
        assertTrue(jwtService.isTokenExpired(token));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void rejectsTokenWithoutMeaningfulSubject(String subject) {
        String token = Jwts.builder().header().keyId(keyId).and().issuer(properties.getIssuer()).subject(subject)
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(signingKey, Jwts.SIG.RS256).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
    }

    @Test
    void rejectsTokenThatIsNotYetValid() {
        String token = Jwts.builder().header().keyId(keyId).and().issuer(properties.getIssuer()).subject(EMAIL)
                .notBefore(Date.from(Instant.now().plusSeconds(60)))
                .expiration(Date.from(Instant.now().plusSeconds(120)))
                .signWith(signingKey, Jwts.SIG.RS256).compact();

        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
    }

    @Test
    void rejectsWeakSigningKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair weakKeys = generator.generateKeyPair();
            properties.setPrivateKey(JwtTestKeys.pem(weakKeys.getPrivate(), "PRIVATE KEY"));
            properties.setPublicKey(JwtTestKeys.pem(weakKeys.getPublic(), "PUBLIC KEY"));
            new JwtService(properties);
        });
    }

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072})
    void alwaysSignsRs256RegardlessOfKeyLength(int keyLength) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keyLength);
        KeyPair keys = generator.generateKeyPair();
        properties.setPrivateKey(JwtTestKeys.pem(keys.getPrivate(), "PRIVATE KEY"));
        properties.setPublicKey(JwtTestKeys.pem(keys.getPublic(), "PUBLIC KEY"));
        JwtService service = new JwtService(properties);
        var parser = Jwts.parser().verifyWith(keys.getPublic()).build();

        for (String token : new String[]{service.generateToken(user), service.generateToken(user, CLIENT_ID),
                service.generateToken(identityDetails), service.generateToken(Map.of(), identityDetails),
                service.generateToken(Map.of("userId", user.getUserId(), "fullName", user.getFullName()), userDetails)}) {
            assertEquals("RS256", parser.parseSignedClaims(token).getHeader().getAlgorithm());
            assertTrue(service.isTokenValid(token, identityDetails));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS384", "RS512", "PS256"})
    void rejectsOtherRsaAlgorithmsEvenWithTheCorrectKey(String algorithm) {
        String token = Jwts.builder().header().keyId(keyId).and().claims(validClaims())
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(signingKey, (io.jsonwebtoken.security.SignatureAlgorithm) Jwts.SIG.get().get(algorithm))
                .compact();

        assertRejected(token);
    }

    @Test
    void rejectsHs256IncludingPublicKeyUsedAsHmacSecret() {
        for (var key : new javax.crypto.SecretKey[]{Jwts.SIG.HS256.key().build(),
                new javax.crypto.spec.SecretKeySpec(publicKey.getEncoded(), "HmacSHA256")}) {
            String token = Jwts.builder().header().keyId(keyId).and().claims(validClaims())
                    .expiration(Date.from(Instant.now().plusSeconds(60)))
                    .signWith(key, Jwts.SIG.HS256).compact();
            assertRejected(token);
        }
    }

    @Test
    void publishesOnlyPublicKeyAndSupportsIndependentVerification() throws Exception {
        var key = jwtService.getJwks().get("keys").getFirst();
        assertEquals(java.util.Set.of("kid", "kty", "alg", "use", "n", "e"), key.keySet());
        assertEquals("RSA", key.get("kty"));
        assertEquals("RS256", key.get("alg"));
        assertEquals("sig", key.get("use"));
        assertEquals(keyId, key.get("kid"));
        var rsa = com.nimbusds.jose.jwk.RSAKey.parse(key);
        assertFalse(rsa.isPrivate());
        assertEquals(publicKey, rsa.toRSAPublicKey());
        var token = com.nimbusds.jwt.SignedJWT.parse(jwtService.generateToken(user));
        assertTrue(token.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(rsa)));
        assertEquals(keyId, token.getHeader().getKeyID());
    }

    @Test
    void generatesEphemeralKeysAndReusesThemWithinServiceInstance() {
        JwtProperties developmentProperties = new JwtProperties();
        developmentProperties.setAllowEphemeralKeys(true);
        JwtService service = new JwtService(developmentProperties);
        var jwks = service.getJwks();
        assertTrue(service.isTokenValid(service.generateToken(user)));
        assertEquals(jwks, service.getJwks());
        JwtService anotherInstance = new JwtService(developmentProperties);
        assertFalse(anotherInstance.isTokenValid(service.generateToken(user)));
        assertFalse(jwks.equals(anotherInstance.getJwks()));
    }

    @Test
    void missingKeysFailClosedUnlessEphemeralKeysAreExplicitlyEnabled() {
        assertThrows(IllegalArgumentException.class, () -> new JwtService(new JwtProperties()));
    }

    @Test
    void configuredKeysKeepTokensAndKeyIdentifierValidAcrossInstances() {
        JwtService anotherInstance = new JwtService(JwtTestKeys.properties());
        assertTrue(anotherInstance.isTokenValid(jwtService.generateToken(user)));
        assertEquals(jwtService.getJwks(), anotherInstance.getJwks());
    }

    @Test
    void acceptsEscapedNewlinesInConfiguredPemKeys() {
        properties.setPrivateKey(properties.getPrivateKey().replace("\n", "\\n"));
        properties.setPublicKey(properties.getPublicKey().replace("\n", "\\n"));
        assertTrue(new JwtService(properties).isTokenValid(jwtService.generateToken(user)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"private", "public"})
    void rejectsIncompleteMalformedAndNonRsaKeyConfiguration(String key) {
        for (String invalid : new String[]{null, "", "not-pem", JwtTestKeys.pem(
                Jwts.SIG.ES256.keyPair().build().getPrivate(), "PRIVATE KEY")}) {
            JwtProperties broken = JwtTestKeys.properties();
            if (key.equals("private")) {
                broken.setPrivateKey(invalid);
            } else {
                broken.setPublicKey(invalid);
            }
            assertThrows(IllegalArgumentException.class, () -> new JwtService(broken));
        }
    }

    @Test
    void rejectsMismatchedKeyPair() {
        properties.setPublicKey(JwtTestKeys.pem(Jwts.SIG.RS256.keyPair().build().getPublic(), "PUBLIC KEY"));
        assertThrows(IllegalArgumentException.class, () -> new JwtService(properties));
    }

    @Test
    void usesConfiguredIssuerAndRejectsTokensFromAnotherIssuerWithSameKey() {
        properties.setIssuer("https://identity.example.com");
        JwtService service = new JwtService(properties);
        String token = service.generateToken(user);
        assertEquals(properties.getIssuer(), service.extractClaim(token, Claims::getIssuer));
        assertTrue(service.isTokenValid(token));
        assertRejected(token);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "https://untrusted.example"})
    void rejectsMissingOrWrongIssuer(String issuer) {
        Map<String, Object> claims = validClaims();
        claims.put("iss", issuer);
        assertRejected(signClaims(claims));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "unknown-key"})
    void rejectsMissingOrUnknownKeyIdentifier(String kid) {
        String token = Jwts.builder().header().keyId(kid).and().claims(validClaims())
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(signingKey, Jwts.SIG.RS256).compact();
        assertRejected(token);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void rejectsBlankIssuerConfiguration(String issuer) {
        properties.setIssuer(issuer);
        assertThrows(IllegalArgumentException.class, () -> new JwtService(properties));
    }

    @Test
    void rejectsLegacyEmailSubjectEvenWithAllOtherClaims() {
        Map<String, Object> claims = validClaims();
        claims.put("sub", EMAIL);
        assertRejected(signClaims(claims));
        claims.remove("email");
        assertRejected(signClaims(claims));
    }

    @Test
    void rejectsInconsistentSubjectAndUserId() {
        Map<String, Object> claims = validClaims();
        claims.put("userId", UUID.randomUUID().toString());
        assertRejected(signClaims(claims));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "userId", "email", "role", "fullName", "clientId"})
    void rejectsMissingBlankAndNonStringRequiredClaims(String name) {
        for (Object invalid : new Object[]{null, "", " ", 123, true, Map.of("value", "invalid")}) {
            Map<String, Object> claims = validClaims();
            claims.put(name, invalid);
            assertRejected(signClaims(claims));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1", "student@example.com",
            "00000000-0000-0000-0000-000000000000 ", "ABCDEF00-0000-0000-0000-000000000000"})
    void rejectsNonCanonicalUuidsEvenWhenBothClaimsMatch(String id) {
        Map<String, Object> claims = validClaims();
        claims.put("sub", id);
        claims.put("userId", id);
        assertRejected(signClaims(claims));
    }

    @Test
    void rejectsDifferentDatabaseUuidEvenWhenEmailMatches() {
        String token = jwtService.generateToken(user);
        user.setUserId(UUID.randomUUID());
        assertFalse(jwtService.isTokenValid(token, new IdentityUserDetails(user)));
    }

    @Test
    void rejectsPrincipalsWithoutDatabaseUuid() {
        String token = jwtService.generateToken(user);
        assertFalse(jwtService.isTokenValid(token, userDetails));
        assertFalse(jwtService.isTokenValid(token, null));
        user.setUserId(null);
        assertFalse(jwtService.isTokenValid(token, new IdentityUserDetails(user)));
    }

    @Test
    void comparesEmailIgnoringCaseButRejectsChangedEmailForSameUuid() {
        String token = jwtService.generateToken(user);
        user.setEmail("STUDENT@EXAMPLE.COM");
        assertTrue(jwtService.isTokenValid(token, new IdentityUserDetails(user)));
        user.setEmail("other@example.com");
        assertFalse(jwtService.isTokenValid(token, new IdentityUserDetails(user)));
    }

    private Map<String, Object> validClaims() {
        return new HashMap<>(Map.of("sub", user.getUserId().toString(),
                "userId", user.getUserId().toString(), "email", EMAIL, "role", "USER",
                "fullName", user.getFullName(), "clientId", CLIENT_ID, "iss", properties.getIssuer()));
    }

    @Test
    void acceptsOmittedAudienceForExistingTokens() {
        assertAccepted(signClaims(validClaims()));
    }

    @ParameterizedTest
    @MethodSource("acceptedAudiences")
    void acceptsAudienceContainingCentralIdentity(Object audience) {
        Map<String, Object> claims = validClaims();
        claims.put("aud", audience);
        assertAccepted(signClaims(claims));
    }

    static Stream<Object> acceptedAudiences() {
        return Stream.of("central-identity", List.of("central-identity"),
                List.of("lms-client", "central-identity"));
    }

    @ParameterizedTest
    @NullSource
    @MethodSource("rejectedAudiences")
    void rejectsForeignOrMalformedAudience(Object audience) {
        Map<String, Object> claims = validClaims();
        claims.put("aud", audience);
        assertRejected(signClaims(claims));
    }

    static Stream<Object> rejectedAudiences() {
        return Stream.of("other-service", CLIENT_ID, "CENTRAL-IDENTITY", " central-identity ",
                List.of("other-service", CLIENT_ID), "", " ", List.of(),
                123, true, Map.of("value", "central-identity"),
                List.of("central-identity", 123), List.of("central-identity", true),
                Arrays.asList("central-identity", null), List.of("central-identity", ""));
    }

    private void assertAccepted(String token) {
        assertTrue(jwtService.isTokenValid(token));
        assertTrue(jwtService.isTokenValid(token, identityDetails));
        assertEquals(EMAIL, jwtService.extractEmail(token));
        assertEquals(user.getUserId().toString(), jwtService.extractUserId(token));
    }

    private String signClaims(Map<String, Object> claims) {
        Map<String, Object> payload = new HashMap<>(claims);
        payload.put("exp", Instant.now().plusSeconds(60).getEpochSecond());
        // Sign raw JSON so the builder cannot reject malformed reserved claims before our parser sees them.
        return Jwts.builder().header().keyId(keyId).and()
                .content(tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsBytes(payload))
                .signWith(signingKey, Jwts.SIG.RS256).compact();
    }

    private void assertRejected(String token) {
        assertFalse(jwtService.isTokenValid(token));
        assertFalse(jwtService.isTokenValid(token, identityDetails));
        assertThrows(JwtException.class, () -> jwtService.extractEmail(token));
        assertThrows(JwtException.class, () -> jwtService.extractUserId(token));
        assertThrows(JwtException.class, () -> jwtService.extractUsername(token));
    }
}
