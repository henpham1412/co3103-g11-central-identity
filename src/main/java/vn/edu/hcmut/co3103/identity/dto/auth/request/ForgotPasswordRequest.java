package vn.edu.hcmut.co3103.identity.dto.auth.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
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
public class ForgotPasswordRequest {

    @JsonProperty("email")
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Utf8ByteLength(message = "Email must be valid Unicode")
    @Size(max = 254, message = "Email must not exceed 254 characters")
    private String email;

    // Jackson may bind through the constructor instead of calling the setter.
    public ForgotPasswordRequest(String email) {
        this.email = normalizeEmail(email);
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

    public static class ForgotPasswordRequestBuilder {
        public ForgotPasswordRequestBuilder email(String email) {
            this.email = normalizeEmail(email);
            return this;
        }
    }
}
