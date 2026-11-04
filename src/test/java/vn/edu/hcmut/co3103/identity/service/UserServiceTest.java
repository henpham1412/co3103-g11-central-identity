package vn.edu.hcmut.co3103.identity.service;

import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.json.JsonMapper;
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

import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static ValidatorFactory validatorFactory;

    @BeforeAll
    static void createValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
    }

    @AfterAll
    static void closeValidator() {
        validatorFactory.close();
    }

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserProfileRepository userProfileRepository;

    private UserService userService;
    private UUID userId;
    private User user;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, userProfileRepository, validatorFactory.getValidator());
        userId = UUID.randomUUID();
        user = User.builder()
                .userId(userId)
                .email("student@example.com")
                .fullName("Nguyen Van A")
                .status(UserStatus.ACTIVE)
                .build();
    }

    @ParameterizedTest
    @MethodSource("vn.edu.hcmut.co3103.identity.support.UnicodeInputs#malformedUnicode")
    void directProfileCallsRejectMalformedUnicodeBeforeAnyMutation(String value) {
        for (String field : new String[]{"full_name", "bio", "avatar_url", "phone_number", "locale", "timezone"}) {
            String text = field.equals("avatar_url") ? "https://example.com/" + value : value;
            var request = JsonMapper.builder().build().readValue("{\"" + field + "\":"
                    + vn.edu.hcmut.co3103.identity.support.UnicodeInputs.jsonString(text) + "}", UpdateProfileRequest.class);
            assertThatThrownBy(() -> userService.updateProfile(userId, request)).isInstanceOf(IllegalArgumentException.class);
        }
        verifyNoInteractions(userRepository, userProfileRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"1899-12-31", "0000-01-01", "9999-12-31"})
    void directProfileCallsEnforceBirthDateRange(String date) {
        var request = UpdateProfileRequest.builder().fullName("Must not persist").dateOfBirth(LocalDate.parse(date)).build();
        assertThatThrownBy(() -> userService.updateProfile(userId, request)).isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(userRepository, userProfileRepository);
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

        when(userRepository.findCurrentProfile(userId)).thenReturn(Optional.of(
                new CurrentUserProfileResponse(userId, user.getEmail(), user.getFullName(), user.getStatus(),
                        profile.getUserId(), profile.getAvatarUrl(), profile.getBio(), profile.getPhoneNumber(),
                        profile.getDateOfBirth(), profile.getLocale(), profile.getTimezone())));

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
        when(userRepository.findCurrentProfile(userId)).thenReturn(Optional.of(
                new CurrentUserProfileResponse(userId, user.getEmail(), user.getFullName(), user.getStatus(), null)));

        CurrentUserProfileResponse response = userService.getCurrentUserProfile(userId);

        assertThat(response.userId()).isEqualTo(userId);
        assertThat(response.email()).isEqualTo("student@example.com");
        assertThat(response.fullName()).isEqualTo("Nguyen Van A");
        assertThat(response.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(response.profile()).isNull();
    }

    @Test
    void getCurrentUserProfileThrowsWhenUserNotFound() {
        when(userRepository.findCurrentProfile(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getCurrentUserProfile(userId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found");
    }

    @Test
    void updateProfileCreatesNewProfileRowWhenNotExists() {
        when(userRepository.findByIdForUpdate(userId)).thenReturn(Optional.of(user));
        when(userProfileRepository.findById(userId)).thenReturn(Optional.empty());
        Instant persistedAt = Instant.parse("2026-10-31T00:00:00.123456Z");
        when(userProfileRepository.saveAndFlush(any(UserProfile.class)))
                .thenReturn(UserProfile.builder().updatedAt(persistedAt).build());

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
        assertThat(response.updatedAt()).isEqualTo(persistedAt);

        assertThat(user.getFullName()).isEqualTo("Nguyen Van A Updated");
        verify(userRepository).save(user);

        ArgumentCaptor<UserProfile> captor = ArgumentCaptor.forClass(UserProfile.class);
        verify(userProfileRepository).saveAndFlush(captor.capture());
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
        Instant persistedAt = Instant.parse("2026-10-31T00:00:00.654321Z");
        when(userProfileRepository.saveAndFlush(existing)).thenAnswer(invocation -> {
            existing.setUpdatedAt(persistedAt);
            return existing;
        });

        UpdateProfileRequest request = UpdateProfileRequest.builder()
                .bio("Brand new bio")
                .build();

        UpdateProfileResponse response = userService.updateProfile(userId, request);

        assertThat(response.message()).isEqualTo("Profile updated successfully");
        assertThat(response.updatedAt()).isEqualTo(persistedAt);
        verify(userRepository, never()).save(any());

        verify(userProfileRepository).saveAndFlush(existing);
        assertThat(existing.getBio()).isEqualTo("Brand new bio");
        assertThat(existing.getAvatarUrl()).isEqualTo("https://example.com/old.png");
        assertThat(existing.getPhoneNumber()).isEqualTo("+84900000000");
    }

    @Test
    void updateProfileThrowsWhenUserNotFound() {
        when(userRepository.findByIdForUpdate(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.updateProfile(userId, UpdateProfileRequest.builder().bio("Update").build()))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"full_name\":null}", "{\"full_name\":null,\"bio\":\"Must not persist\"}"})
    void invalidPatchIsRejectedBeforeAnyRepositoryAccess(String json) {
        var request = JsonMapper.builder().build().readValue(json, UpdateProfileRequest.class);
        assertThatThrownBy(() -> userService.updateProfile(userId, request))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(userRepository, userProfileRepository);
    }
}
