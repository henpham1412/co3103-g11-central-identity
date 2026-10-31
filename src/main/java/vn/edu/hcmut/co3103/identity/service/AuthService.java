package vn.edu.hcmut.co3103.identity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.config.LoginPolicyProperties;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.response.AuthResponse;
import vn.edu.hcmut.co3103.identity.dto.auth.response.RegisterResponse;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.AccountInactiveException;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.DuplicateEmailException;
import vn.edu.hcmut.co3103.identity.exception.DataIntegrityViolationClassifier;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.exception.InvalidClientException;
import vn.edu.hcmut.co3103.identity.exception.InvalidRedirectUriException;
import vn.edu.hcmut.co3103.identity.repository.LmsClientRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    // Match the default BCrypt cost used by SecurityConfig; compute once, not per request.
    private static final String DUMMY_PASSWORD_HASH =
            new BCryptPasswordEncoder().encode("dummy-password-for-nonexistent-user");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final LmsClientRepository lmsClientRepository;
    private final LoginPolicyProperties loginPolicyProperties;

    @Transactional(readOnly = false)
    public RegisterResponse register(RegisterRequest request) {
        String password = request.getPassword();
        if (password == null || password.isBlank() || password.length() < 8
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("Password does not meet the password policy");
        }
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateEmailException("Email already exists: " + email);
        }

        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName().trim())
                .status(UserStatus.ACTIVE)
                .failedLoginAttempts(0)
                .build();
        User savedUser;
        try {
            savedUser = userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            if (DataIntegrityViolationClassifier.isEmailUniqueViolation(e)) {
                throw new DuplicateEmailException("Email already exists: " + email);
            }
            throw e;
        }

        return RegisterResponse.builder()
                .userId(savedUser.getUserId())
                .email(savedUser.getEmail())
                .fullName(savedUser.getFullName())
                .status(savedUser.getStatus())
                .build();
    }

    // Failed attempts and lockouts must be committed even when authentication is rejected.
    @Transactional(readOnly = false,
            noRollbackFor = {InvalidCredentialsException.class, AccountLockedException.class})
    public AuthResponse login(LoginRequest request) {
        // Also protect callers that bypass HTTP bean validation, before any BCrypt work.
        if (request.getPassword() != null && request.getPassword().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new InvalidCredentialsException("Invalid email or password");
        }
        String clientId = validateClientContext(request);
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmailForUpdate(email)
                .orElseThrow(() -> {
                    passwordEncoder.matches(request.getPassword(), DUMMY_PASSWORD_HASH);
                    return new InvalidCredentialsException("Invalid email or password");
                });

        // Do not disclose status or lockout information until credentials have been verified.
        boolean passwordMatches = passwordEncoder.matches(request.getPassword(), user.getPasswordHash());
        Instant now = Instant.now();
        if (user.getLockedUntil() != null && !now.isBefore(user.getLockedUntil())) {
            user.setLockedUntil(null);
            user.setFailedLoginAttempts(0);
        }

        if (!passwordMatches) {
            int attempts = (user.getFailedLoginAttempts() == null ? 0 : user.getFailedLoginAttempts()) + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= loginPolicyProperties.getMaxFailedAttempts() && user.getLockedUntil() == null) {
                user.setLockedUntil(now.plus(loginPolicyProperties.getLockoutDuration()));
            }
            userRepository.save(user);
            throw new InvalidCredentialsException("Invalid email or password");
        }

        if (user.getLockedUntil() != null) {
            throw new AccountLockedException(
                    "Account is temporarily locked until " + user.getLockedUntil(), user.getLockedUntil());
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AccountInactiveException("Account is inactive");
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);
        String token = jwtService.generateToken(user, clientId);
        long expiresInSeconds = jwtProperties.getExpirationMs() / 1000;
        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresIn(expiresInSeconds)
                .clientId(clientId)
                .user(new AuthResponse.AuthUser(user.getUserId(), user.getEmail(),
                        user.getFullName(), user.getStatus()))
                .build();
    }

    private String validateClientContext(LoginRequest request) {
        String clientId = request.getClientId();
        String redirectUri = request.getRedirectUri();
        if (clientId == null) {
            if (redirectUri != null) {
                throw new InvalidRedirectUriException();
            }
            return "central-identity";
        }
        var client = lmsClientRepository.findByClientIdAndIsActiveTrue(clientId)
                .orElseThrow(InvalidClientException::new);
        // Compare the complete registered value; do not normalize or accept prefix matches.
        if (redirectUri != null && (redirectUri.isBlank() || client.getRedirectUris() == null
                || !client.getRedirectUris().contains(redirectUri))) {
            throw new InvalidRedirectUriException();
        }
        return clientId;
    }
}
