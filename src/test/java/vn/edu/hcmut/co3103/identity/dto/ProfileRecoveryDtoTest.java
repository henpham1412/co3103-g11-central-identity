package vn.edu.hcmut.co3103.identity.dto;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.exc.UnrecognizedPropertyException;
import tools.jackson.databind.json.JsonMapper;
import vn.edu.hcmut.co3103.identity.config.WebMvcConfig;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.common.MessageResponse;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;
import vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse;
import vn.edu.hcmut.co3103.identity.dto.user.response.UpdateProfileResponse;
import vn.edu.hcmut.co3103.identity.dto.user.response.UserProfileResponse;
import vn.edu.hcmut.co3103.identity.entity.UserStatus;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProfileRecoveryDtoTest {

    private static final Instant NOW = Instant.parse("2026-10-31T00:00:00Z");
    private static ValidatorFactory factory;
    private static Validator validator;
    private static ObjectMapper mapper;

    @BeforeAll
    static void setUp() {
        factory = Validation.byDefaultProvider().configure()
                .clockProvider(() -> Clock.fixed(NOW, ZoneOffset.UTC)).buildValidatorFactory();
        validator = factory.getValidator();
        var builder = JsonMapper.builder();
        new WebMvcConfig().strictJsonRequests().customize(builder);
        mapper = builder.build();
    }

    @AfterAll
    static void closeValidatorFactory() {
        factory.close();
    }

    @Test
    void readsRecoveryRequestsWithDocumentedKeysAndNormalizesEmail() {
        var forgot = mapper.readValue("""
                {"email":"  Student@Example.COM  "}
                """, ForgotPasswordRequest.class);
        assertThat(forgot.getEmail()).isEqualTo("student@example.com");
        assertThat(validator.validate(forgot)).isEmpty();

        String json = """
                {"token":"reset-token","new_password":"SecurePassword123!"}
                """;
        var reset = mapper.readValue(json, ResetPasswordRequest.class);
        assertThat(reset.getToken()).isEqualTo("reset-token");
        assertThat(reset.getNewPassword()).isEqualTo("SecurePassword123!");
        assertThat(validator.validate(reset)).isEmpty();
        assertThat(mapper.readTree(mapper.writeValueAsString(reset))).isEqualTo(mapper.readTree(json));
        assertThrows(UnrecognizedPropertyException.class, () -> mapper.readValue(
                "{\"token\":\"reset-token\",\"newPassword\":\"SecurePassword123!\"}", ResetPasswordRequest.class));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "invalid-email"})
    void rejectsInvalidRecoveryEmails(String email) {
        assertThat(validator.validate(ForgotPasswordRequest.builder().email(email).build())).isNotEmpty();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void rejectsMissingResetTokens(String token) {
        assertThat(validator.validate(ResetPasswordRequest.builder()
                .token(token).newPassword("SecurePassword123!").build()))
                .anyMatch(violation -> violation.getPropertyPath().toString().equals("token"));
    }

    @Test
    void roundTripsAllProfileUpdateFieldsUsingSnakeCaseAndIsoDate() {
        String json = """
                {"full_name":"Nguyen Van A","avatar_url":"https://storage.example.com/avatar.png",
                 "bio":"Computer Science student","phone_number":"+84912345678",
                 "date_of_birth":"2000-01-02","locale":"vi-VN","timezone":"Asia/Ho_Chi_Minh"}
                """;
        var request = mapper.readValue(json, UpdateProfileRequest.class);
        assertThat(request.getFullName()).isEqualTo("Nguyen Van A");
        assertThat(request.getDateOfBirth()).isEqualTo(LocalDate.of(2000, 1, 2));
        assertThat(validator.validate(request)).isEmpty();
        assertThat(mapper.readTree(mapper.writeValueAsString(request))).isEqualTo(mapper.readTree(json));
    }

    @Test
    void allowsPartialProfileUpdatesAndNullableProfileFields() {
        assertThat(validator.validate(mapper.readValue("{}", UpdateProfileRequest.class))).isEmpty();
        var request = mapper.readValue("""
                {"bio":"New biography","avatar_url":null,"phone_number":null,
                 "date_of_birth":null,"locale":null,"timezone":null}
                """, UpdateProfileRequest.class);
        assertThat(request.getFullName()).isNull();
        assertThat(request.getBio()).isEqualTo("New biography");
        assertThat(validator.validate(request)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"fullName", "avatarUrl", "phoneNumber", "dateOfBirth", "email", "user_id", "status", "suppliedFields"})
    void rejectsUndocumentedOrProtectedProfileFields(String field) {
        assertThrows(UnrecognizedPropertyException.class,
                () -> mapper.readValue("{\"" + field + "\":null}", UpdateProfileRequest.class));
    }

    @Test
    void enforcesSchemaLengthLimitsWithoutRequiringOptionalFields() {
        var request = UpdateProfileRequest.builder().fullName("a".repeat(150))
                .phoneNumber("1".repeat(30)).locale("a".repeat(20)).timezone("a".repeat(64)).build();
        assertThat(validator.validate(request)).isEmpty();
        request.setFullName("a".repeat(151));
        request.setPhoneNumber("1".repeat(31));
        request.setLocale("a".repeat(21));
        request.setTimezone("a".repeat(65));
        assertThat(validator.validate(request)).extracting(violation -> violation.getPropertyPath().toString())
                .containsExactlyInAnyOrder("fullName", "phoneNumber", "locale", "timezone");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t\n"})
    void rejectsBlankFullNameWhenSupplied(String fullName) {
        assertThat(validator.validate(UpdateProfileRequest.builder().fullName(fullName).build())).isNotEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-url", "javascript:alert(1)", "ftp://storage.example.com/avatar.png"})
    void rejectsInvalidAvatarUrls(String avatarUrl) {
        assertThat(validator.validate(UpdateProfileRequest.builder().avatarUrl(avatarUrl).build())).isNotEmpty();
    }

    @Test
    void rejectsFutureBirthDatesButAcceptsToday() {
        var request = UpdateProfileRequest.builder().dateOfBirth(LocalDate.of(2026, 10, 31)).build();
        assertThat(validator.validate(request)).isEmpty();
        request.setDateOfBirth(LocalDate.of(2026, 11, 1));
        assertThat(validator.validate(request)).extracting(violation -> violation.getPropertyPath().toString())
                .containsExactly("dateOfBirth");
    }

    @Test
    void serializesCurrentProfileWithDocumentedFieldsAndLegacyIdentityAliases() {
        UUID userId = UUID.randomUUID();
        var profile = new UserProfileResponse("https://storage.example.com/avatar.png", "Student", "+84912345678",
                LocalDate.of(2000, 1, 2), "vi-VN", "Asia/Ho_Chi_Minh");
        var response = new CurrentUserProfileResponse(userId, "student@example.com", "Nguyen Van A",
                UserStatus.ACTIVE, profile);
        var json = mapper.readTree(mapper.writeValueAsString(response));
        assertThat(json.propertyNames()).containsExactlyInAnyOrder(
                "user_id", "email", "full_name", "status", "profile", "id", "fullName", "role");
        assertThat(json.get("user_id").asString()).isEqualTo(userId.toString());
        assertThat(json.get("id")).isEqualTo(json.get("user_id"));
        assertThat(json.get("fullName")).isEqualTo(json.get("full_name"));
        assertThat(json.get("role").asString()).isEqualTo("USER");
        assertThat(json.get("profile")).isEqualTo(mapper.readTree("""
                {"avatar_url":"https://storage.example.com/avatar.png","bio":"Student",
                 "phone_number":"+84912345678","date_of_birth":"2000-01-02",
                 "locale":"vi-VN","timezone":"Asia/Ho_Chi_Minh"}
                """));
        var missingProfile = new CurrentUserProfileResponse(userId, "student@example.com", "Nguyen Van A",
                UserStatus.ACTIVE, null);
        assertThat(mapper.readTree(mapper.writeValueAsString(missingProfile)).get("profile").isNull()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"avatar_url", "bio", "phone_number", "date_of_birth", "locale", "timezone"})
    void distinguishesExplicitNullFromAnOmittedProfileField(String field) {
        var omitted = mapper.readValue("{}", UpdateProfileRequest.class);
        var explicitNull = mapper.readValue("{\"" + field + "\":null}", UpdateProfileRequest.class);
        assertThat(omitted.hasField(field)).isFalse();
        assertThat(explicitNull.hasField(field)).isTrue();
        assertThat(validator.validate(explicitNull)).isEmpty();
    }

    @Test
    void serializesRecoveryMessagesAndProfileUpdateTimestamp() {
        assertThat(mapper.readTree(mapper.writeValueAsString(new MessageResponse("Recovery requested"))))
                .isEqualTo(mapper.readTree("{\"message\":\"Recovery requested\"}"));
        var response = new UpdateProfileResponse("Profile updated successfully", NOW);
        assertThat(mapper.readTree(mapper.writeValueAsString(response))).isEqualTo(mapper.readTree("""
                {"message":"Profile updated successfully","updated_at":"2026-10-31T00:00:00Z"}
                """));
    }
}
