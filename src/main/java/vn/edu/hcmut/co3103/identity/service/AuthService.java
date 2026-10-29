package vn.edu.hcmut.co3103.identity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.config.JwtProperties;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.response.AuthResponse;
import vn.edu.hcmut.co3103.identity.dto.auth.response.RegisterResponse;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.AccountInactiveException;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.DuplicateEmailException;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import java.time.Duration;
import java.time.Instant;
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

    @Transactional(readOnly = false)
    public RegisterResponse register(RegisterRequest request) {
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
            throw new DuplicateEmailException("Email already exists: " + email);
        }

        return RegisterResponse.builder()
                .userId(savedUser.getUserId())
                .email(savedUser.getEmail())
                .fullName(savedUser.getFullName())
                .status(savedUser.getStatus())
                .createdAt(savedUser.getCreatedAt())
                .build();
    }

    // Failed attempts and lockouts must be committed even when authentication is rejected.
    @Transactional(readOnly = false,
            noRollbackFor = {InvalidCredentialsException.class, AccountLockedException.class})
    public AuthResponse login(LoginRequest request) {
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmailForUpdate(email)
                .orElseThrow(() -> {
                    passwordEncoder.matches(request.getPassword(), DUMMY_PASSWORD_HASH);
                    return new InvalidCredentialsException("Invalid email or password");
                });

        if (user.getStatus() == UserStatus.INACTIVE) {
            throw new AccountInactiveException("Account is inactive");
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        Instant now = Instant.now();
        if (user.getLockedUntil() != null) {
            if (now.isBefore(user.getLockedUntil())) {
                throw new AccountLockedException(
                        "Account is temporarily locked until " + user.getLockedUntil(), user.getLockedUntil());
            }
            user.setLockedUntil(null);
            user.setFailedLoginAttempts(0);
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            int attempts = (user.getFailedLoginAttempts() == null ? 0 : user.getFailedLoginAttempts()) + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= 5) {
                user.setLockedUntil(Instant.now().plus(Duration.ofMinutes(15)));
            }
            userRepository.save(user);
            if (user.getLockedUntil() != null) {
                throw new AccountLockedException(
                        "Account is locked due to 5 consecutive failed login attempts", user.getLockedUntil());
            }
            throw new InvalidCredentialsException("Invalid email or password");
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);
        String token = jwtService.generateToken(user);
        long expiresInSeconds = jwtProperties.getExpirationMs() / 1000;
        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresIn(expiresInSeconds)
                .userId(user.getUserId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .status(user.getStatus())
                .build();
    }
}
