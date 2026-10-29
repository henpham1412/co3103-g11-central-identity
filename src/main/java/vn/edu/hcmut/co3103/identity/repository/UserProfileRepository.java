package vn.edu.hcmut.co3103.identity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.edu.hcmut.co3103.identity.entity.UserProfile;

import java.util.UUID;

public interface UserProfileRepository extends JpaRepository<UserProfile, UUID> {
}
