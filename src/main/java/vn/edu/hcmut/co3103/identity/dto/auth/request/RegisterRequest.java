package vn.edu.hcmut.co3103.identity.dto.auth.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import vn.edu.hcmut.co3103.identity.validation.Utf8ByteLength;

import java.util.Locale;

@Getter
@Setter
@Builder
@NoArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 254, message = "Email must not exceed 254 characters")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Utf8ByteLength(max = 72, message = "Password must not exceed 72 UTF-8 bytes")
    private String password;

    @NotBlank(message = "Full name is required")
    @Size(max = 150, message = "Full name must not exceed 150 characters")
    @Pattern(regexp = "^[^\\p{Cc}]*$", message = "Full name contains invalid characters")
    @JsonProperty("full_name")
    private String fullName;

    @Size(min = 1, max = 100, message = "Client ID must be between 1 and 100 characters")
    @Pattern(regexp = "\\S+", message = "Client ID must not contain whitespace")
    @JsonProperty("client_id")
    private String clientId;

    // Jackson can choose the property-based constructor instead of calling setters.
    public RegisterRequest(String email, String password, String fullName, String clientId) {
        this.email = normalizeEmail(email);
        this.password = password;
        this.fullName = fullName;
        this.clientId = clientId;
    }

    private static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    @JsonSetter("email")
    public void setEmail(String email) {
        this.email = normalizeEmail(email);
    }

    public String getEmail() {
        return normalizeEmail(email);
    }

    public static class RegisterRequestBuilder {
        public RegisterRequestBuilder email(String email) {
            this.email = normalizeEmail(email);
            return this;
        }
    }
}
