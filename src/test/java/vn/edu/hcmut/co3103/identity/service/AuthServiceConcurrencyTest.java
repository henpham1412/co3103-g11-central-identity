package vn.edu.hcmut.co3103.identity.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import vn.edu.hcmut.co3103.identity.dto.auth.request.LoginRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.RegisterRequest;
import vn.edu.hcmut.co3103.identity.exception.DuplicateEmailException;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.exception.AccountLockedException;
import vn.edu.hcmut.co3103.identity.exception.InvalidCredentialsException;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class AuthServiceConcurrencyTest {

    @Autowired
    private AuthService authService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManager entityManager;

    private String email;

    @BeforeEach
    void createUser() {
        email = "concurrency-" + UUID.randomUUID() + "@example.com";
        userRepository.saveAndFlush(User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode("CorrectPassword123!"))
                .fullName("Concurrency Test")
                .build());
    }

    @AfterEach
    void removeUser() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status ->
                userRepository.findByEmail(email).ifPresent(userRepository::delete));
    }

    @Test
    void repositoryQueryAcquiresPessimisticWriteLock() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            User lockedUser = userRepository.findByEmailForUpdate(email).orElseThrow();

            assertEquals(LockModeType.PESSIMISTIC_WRITE, entityManager.getLockMode(lockedUser));
        });
    }

    @Test
    void concurrentRegistrationsCreateExactlyOneAccountAndReportOnlyEmailConflicts() throws Exception {
        userRepository.findByEmail(email).ifPresent(userRepository::delete);
        int requestCount = 4;
        CountDownLatch ready = new CountDownLatch(requestCount);
        CountDownLatch start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(requestCount);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < requestCount; i++) {
                results.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(10, TimeUnit.SECONDS));
                    try {
                        authService.register(RegisterRequest.builder().email(email)
                                .password("CorrectPassword123!").fullName("Concurrent Registration").build());
                        return true;
                    } catch (DuplicateEmailException exception) {
                        return false;
                    }
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            int successes = 0;
            for (Future<Boolean> result : results) {
                if (result.get(20, TimeUnit.SECONDS)) {
                    successes++;
                }
            }
            assertEquals(1, successes);
            assertTrue(userRepository.findByEmail(email).isPresent());
        } finally {
            start.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void concurrentFailedLoginsStopPasswordChecksAndCounterAtLockThreshold() throws Exception {
        int requestCount = 8;
        CountDownLatch ready = new CountDownLatch(requestCount);
        CountDownLatch start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(requestCount);
        List<Future<RuntimeException>> results = new ArrayList<>();
        try {
            for (int i = 0; i < requestCount; i++) {
                results.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(10, TimeUnit.SECONDS), "Concurrent login start timed out");
                    LoginRequest request = LoginRequest.builder()
                            .email(email).password("WrongPassword123!").build();
                    return assertThrows(RuntimeException.class, () -> authService.login(request));
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS), "Login workers did not become ready");
            start.countDown();

            List<Class<?>> failures = new ArrayList<>();
            for (Future<RuntimeException> result : results) {
                failures.add(result.get(20, TimeUnit.SECONDS).getClass());
            }
            assertEquals(5, failures.stream().filter(InvalidCredentialsException.class::equals).count());
            assertEquals(requestCount - 5, failures.stream().filter(AccountLockedException.class::equals).count());

            User savedUser = userRepository.findByEmail(email).orElseThrow();
            assertEquals(5, savedUser.getFailedLoginAttempts());
            assertNotNull(savedUser.getLockedUntil());
            assertTrue(savedUser.getLockedUntil().isAfter(Instant.now()));
            AccountLockedException locked = assertThrows(AccountLockedException.class, () -> authService.login(
                    LoginRequest.builder().email(email).password("CorrectPassword123!").build()));
            assertEquals(savedUser.getLockedUntil(), locked.getLockedUntil());
        } finally {
            start.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS), "Login workers did not stop");
        }
    }
}
