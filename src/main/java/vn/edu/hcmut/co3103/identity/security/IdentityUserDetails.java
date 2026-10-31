package vn.edu.hcmut.co3103.identity.security;

import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** An authenticated database identity, including the immutable account identifier. */
public final class IdentityUserDetails extends org.springframework.security.core.userdetails.User {

    private final UUID userId;
    private final String fullName;
    private final UserStatus status;

    public IdentityUserDetails(User user) {
        super(user.getEmail(), user.getPasswordHash(), user.getStatus() == UserStatus.ACTIVE,
                true, true, user.getLockedUntil() == null || !user.getLockedUntil().isAfter(Instant.now()),
                List.of());
        this.userId = user.getUserId();
        this.fullName = user.getFullName();
        this.status = user.getStatus();
    }

    public UUID getUserId() {
        return userId;
    }

    public String getFullName() {
        return fullName;
    }

    public UserStatus getStatus() {
        return status;
    }
}
