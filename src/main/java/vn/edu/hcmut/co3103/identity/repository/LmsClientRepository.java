package vn.edu.hcmut.co3103.identity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.edu.hcmut.co3103.identity.entity.LmsClient;

import java.util.Optional;

public interface LmsClientRepository extends JpaRepository<LmsClient, String> {

    Optional<LmsClient> findByClientIdAndIsActiveTrue(String clientId);
}
