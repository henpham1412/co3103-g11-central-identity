package vn.edu.hcmut.co3103.identity.dto.user.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.URL;

import java.time.LocalDate;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequest {

    @JsonProperty("full_name")
    @Size(max = 150, message = "Full name must not exceed 150 characters")
    @Pattern(regexp = "(?s).*\\S.*", message = "Full name must not be blank")
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
}
