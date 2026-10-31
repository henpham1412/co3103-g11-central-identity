package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;
import vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse;
import vn.edu.hcmut.co3103.identity.dto.user.response.UpdateProfileResponse;
import vn.edu.hcmut.co3103.identity.entity.User;
import vn.edu.hcmut.co3103.identity.entity.UserProfile;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;
import vn.edu.hcmut.co3103.identity.exception.ResourceNotFoundException;
import vn.edu.hcmut.co3103.identity.repository.UserProfileRepository;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserProfileRepository userProfileRepository;

    private UserService userService;
    private UUID userId;
    private User user;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, userProfileRepository);
        userId = UUID.randomUUID();
        user = User.builder()
                .userId(userId)
                .email("student@example.com")
                .fullName("Nguyen Van A")
                .status(UserStatus.ACTIVE)
                .build();
    }

    @Test
    void getCurrentUserProfileReturnsProfileWhenExists() {
        UserProfile profile = new UserProfile();
        profile.setUserId(userId);
        profile.setAvatarUrl("https://example.com/avatar.png");
        profile.setBio("My bio");
        profile.setPhoneNumber("+84901234567");
        profile.setDateOfBirth(LocalDate.of(2000, 1, 1));
        profile.setLocale("vi-VN");
        profile.setTimezone("Asia/Ho_Chi_Minh");

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userProfileRepository.findById(userId)).thenReturn(Optional.of(profile));

        CurrentUserProfileResponse response = userService.getCurrentUserProfile(userId);

        assertThat(response.userId()).isEqualTo(userId);
        assertThat(response.email()).isEqualTo("student@example.com");
        assertThat(response.fullName()).isEqualTo("Nguyen Van A");
        assertThat(response.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(response.profile()).isNotNull();
        assertThat(response.profile().avatarUrl()).isEqualTo("https://example.com/avatar.png");
        assertThat(response.profile().bio()).isEqualTo("My bio");
        assertThat(response.profile().phoneNumber()).isEqualTo("+84901234567");
        assertThat(response.profile().dateOfBirth()).isEqualTo(LocalDate.of(2000, 1, 1));
        assertThat(response.profile().locale()).isEqualTo("vi-VN");
        assertThat(response.profile().timezone()).isEqualTo("Asia/Ho_Chi_Minh");
    }

    @Test
    void getCurrentUserProfileReturnsNullProfileWhenProfileMissing() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userProfileRepository.findById(userId)).thenReturn(Optional.empty());

        CurrentUserProfileResponse response = userService.getCurrentUserProfile(userId);

        assertThat(response.userId()).isEqualTo(userId);
        assertThat(response.email()).isEqualTo("student@example.com");
        assertThat(response.fullName()).isEqualTo("Nguyen Van A");
        assertThat(response.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(response.profile()).isNull();
    }

    @Test
    void getCurrentUserProfileThrowsWhenUserNotFound() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getCurrentUserProfile(userId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found");
    }

    @Test
    void updateProfileCreatesNewProfileRowWhenNotExists() {
        when(userRepository.findByIdForUpdate(userId)).thenReturn(Optional.of(user));
        when(userProfileRepository.findById(userId)).thenReturn(Optional.empty());

        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .fullName("Nguyen Van A Updated")
                .avatarUrl("https://example.com/new-avatar.png")
                .bio("Updated Bio")
                .phoneNumber("+84987654321")
                .dateOfBirth(LocalDate.of(1999, 12, 31))
                .locale("en-US")
                .timezone("UTC")
                .build();

        UpdateProfileResponse response = userService.updateProfile(userId, request);

        assertThat(response.message()).isEqualTo("Profile updated successfully");
        assertThat(response.updatedAt()).isNotNull();

        assertThat(user.getFullName()).isEqualTo("Nguyen Van A Updated");
        verify(userRepository).save(user);

        ArgumentCaptor<UserProfile> captor = ArgumentCaptor.forClass(UserProfile.class);
        verify(userProfileRepository).save(captor.capture());
        UserProfile saved = captor.getValue();
        assertThat(saved.getUserId()).isNull();
        assertThat(saved.getUser()).isSameAs(user);
        verify(userRepository, never()).findById(userId);
        assertThat(saved.getAvatarUrl()).isEqualTo("https://example.com/new-avatar.png");
        assertThat(saved.getBio()).isEqualTo("Updated Bio");
        assertThat(saved.getPhoneNumber()).isEqualTo("+84987654321");
        assertThat(saved.getDateOfBirth()).isEqualTo(LocalDate.of(1999, 12, 31));
        assertThat(saved.getLocale()).isEqualTo("en-US");
        assertThat(saved.getTimezone()).isEqualTo("UTC");
        assertThat(saved.getUpdatedAt()).isNotNull();
    }

    @Test
    void updateProfileUpdatesExistingProfileFieldsSelectively() {
        UserProfile existing = new UserProfile();
        existing.setUserId(userId);
        existing.setAvatarUrl("https://example.com/old.png");
        existing.setBio("Old bio");
        existing.setPhoneNumber("+84900000000");

        when(userRepository.findByIdForUpdate(userId)).thenReturn(Optional.of(user));
        when(userProfileRepository.findById(userId)).thenReturn(Optional.of(existing));

        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .bio("Brand new bio")
                .build();

        UpdateProfileResponse response = userService.updateProfile(userId, request);

        assertThat(response.message()).isEqualTo("Profile updated successfully");
        verify(userRepository, never()).save(any());

        verify(userProfileRepository).save(existing);
        assertThat(existing.getBio()).isEqualTo("Brand new bio");
        assertThat(existing.getAvatarUrl()).isEqualTo("https://example.com/old.png");
        assertThat(existing.getPhoneNumber()).isEqualTo("+84900000000");
    }

    @Test
    void updateProfileThrowsWhenUserNotFound() {
        when(userRepository.findByIdForUpdate(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.updateProfile(userId, new UpdateProfileRequest()))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found");
    }
}
