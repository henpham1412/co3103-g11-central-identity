package vn.edu.hcmut.co3103.identity.repository;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    @Query("""
            select new vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse(
                u.userId, u.email, u.fullName, u.status, p.userId, p.avatarUrl, p.bio,
                p.phoneNumber, p.dateOfBirth, p.locale, p.timezone)
            from User u left join UserProfile p on p.userId = u.userId
            where u.userId = :userId
            """)
    Optional<CurrentUserProfileResponse> findCurrentProfile(@Param("userId") UUID userId);

    Optional<User> findByEmail(String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.userId = :userId")
    Optional<User> findByIdForUpdate(@Param("userId") UUID userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.email = :email")
    Optional<User> findByEmailForUpdate(@Param("email") String email);

    boolean existsByEmail(String email);
}
