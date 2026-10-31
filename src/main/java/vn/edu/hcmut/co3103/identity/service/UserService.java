package vn.edu.hcmut.co3103.identity.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;
import vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse;
import vn.edu.hcmut.co3103.identity.dto.user.response.UpdateProfileResponse;
import vn.edu.hcmut.co3103.identity.dto.user.response.UserProfileResponse;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserProfile;
import vn.edu.hcmut.co3103.identity.exception.ResourceNotFoundException;
import vn.edu.hcmut.co3103.identity.repository.UserProfileRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.time.Instant;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;

    public UserService(UserRepository userRepository, UserProfileRepository userProfileRepository) {
        this.userRepository = userRepository;
        this.userProfileRepository = userProfileRepository;
    }

    @Transactional(readOnly = true)
    public CurrentUserProfileResponse getCurrentUserProfile(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        UserProfileResponse profileResponse = userProfileRepository.findById(userId)
                .map(this::toUserProfileResponse)
                .orElse(null);

        return new CurrentUserProfileResponse(
                user.getUserId(),
                user.getEmail(),
                user.getFullName(),
                user.getStatus(),
                profileResponse
        );
    }

    @Transactional
    public UpdateProfileResponse updateProfile(UUID userId, UpdateProfileRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (request.getFullName() != null) {
            user.setFullName(request.getFullName());
            userRepository.save(user);
        }

        UserProfile profile = userProfileRepository.findById(userId).orElse(null);
        if (profile == null) {
            profile = new UserProfile();
            profile.setUserId(userId);
            profile.setUser(user);
        }

        if (request.getAvatarUrl() != null) {
            profile.setAvatarUrl(request.getAvatarUrl());
        }
        if (request.getBio() != null) {
            profile.setBio(request.getBio());
        }
        if (request.getPhoneNumber() != null) {
            profile.setPhoneNumber(request.getPhoneNumber());
        }
        if (request.getDateOfBirth() != null) {
            profile.setDateOfBirth(request.getDateOfBirth());
        }
        if (request.getLocale() != null) {
            profile.setLocale(request.getLocale());
        }
        if (request.getTimezone() != null) {
            profile.setTimezone(request.getTimezone());
        }

        Instant now = Instant.now();
        profile.setUpdatedAt(now);
        userProfileRepository.save(profile);

        return new UpdateProfileResponse("Profile updated successfully", now);
    }

    private UserProfileResponse toUserProfileResponse(UserProfile profile) {
        return new UserProfileResponse(
                profile.getAvatarUrl(),
                profile.getBio(),
                profile.getPhoneNumber(),
                profile.getDateOfBirth(),
                profile.getLocale(),
                profile.getTimezone()
        );
    }
}
