package vn.edu.hcmut.co3103.identity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.entity.PasswordReset;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetRepository extends JpaRepository<PasswordReset, UUID> {

    Optional<PasswordReset> findByTokenHash(String tokenHash);

    List<PasswordReset> findByUserIdOrderByCreatedAtDesc(UUID userId);

    @Transactional
    void deleteByUserId(UUID userId);
}
