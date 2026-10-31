package vn.edu.hcmut.co3103.identity.dto.user.response;

import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.util.UUID;

public record CurrentUserResponse(UUID id, String email, String fullName, UserStatus status, String role) {
}
