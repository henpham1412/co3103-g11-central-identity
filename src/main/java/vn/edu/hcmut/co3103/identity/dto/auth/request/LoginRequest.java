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
public class LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 254, message = "Email must not exceed 254 characters")
    private String email;

    @NotBlank(message = "Password is required")
    @Utf8ByteLength(max = 72, message = "Password must be valid Unicode and not exceed 72 UTF-8 bytes")
    private String password;

    @Size(min = 1, max = 100, message = "Client ID must be between 1 and 100 characters")
    @Pattern(regexp = "\\S+", message = "Client ID must not contain whitespace")
    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    // Keep normalization identical for constructor- and setter-based JSON binding.
    public LoginRequest(String email, String password, String clientId, String redirectUri) {
        this.email = normalizeEmail(email);
        this.password = password;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
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

    public static class LoginRequestBuilder {
        public LoginRequestBuilder email(String email) {
            this.email = normalizeEmail(email);
            return this;
        }
    }
}
