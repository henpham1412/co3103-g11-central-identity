package vn.edu.hcmut.co3103.identity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.edu.hcmut.co3103.identity.entity.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
