package vn.edu.hcmut.co3103.identity.dto.user.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonSetter;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.URL;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor(onConstructor_ = @JsonCreator)
@AllArgsConstructor
public class UpdateProfileRequest {

    // Setters are called for explicit JSON nulls, but not for omitted properties.
    @Getter(AccessLevel.NONE)
    private final Set<String> suppliedFields = new HashSet<>();

    @JsonProperty("full_name")
    @Size(max = 150, message = "Full name must not exceed 150 characters")
    // javaWhitespace delegates to Character.isWhitespace, matching String.isBlank().
    @Pattern(regexp = "(?s).*\\P{javaWhitespace}.*", message = "Full name must not be blank")
    private String fullName;

    @JsonProperty("avatar_url")
    @URL(regexp = "https?://.*", message = "Avatar URL must be a valid HTTP or HTTPS URL")
    private String avatarUrl;

    @JsonProperty("bio")
    private String bio;

    @JsonProperty("phone_number")
    @Size(max = 30, message = "Phone number must not exceed 30 characters")
    private String phoneNumber;

    @JsonProperty("date_of_birth")
    @PastOrPresent(message = "Date of birth must not be in the future")
    private LocalDate dateOfBirth;

    @JsonProperty("locale")
    @Size(max = 20, message = "Locale must not exceed 20 characters")
    private String locale;

    @JsonProperty("timezone")
    @Size(max = 64, message = "Timezone must not exceed 64 characters")
    private String timezone;

    public boolean hasField(String field) {
        return suppliedFields.contains(field);
    }

    @JsonSetter("avatar_url")
    public void setAvatarUrl(String avatarUrl) {
        this.avatarUrl = avatarUrl;
        suppliedFields.add("avatar_url");
    }

    @JsonSetter("bio")
    public void setBio(String bio) {
        this.bio = bio;
        suppliedFields.add("bio");
    }

    @JsonSetter("phone_number")
    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        suppliedFields.add("phone_number");
    }

    @JsonSetter("date_of_birth")
    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
        suppliedFields.add("date_of_birth");
    }

    @JsonSetter("locale")
    public void setLocale(String locale) {
        this.locale = locale;
        suppliedFields.add("locale");
    }

    @JsonSetter("timezone")
    public void setTimezone(String timezone) {
        this.timezone = timezone;
        suppliedFields.add("timezone");
    }
}
