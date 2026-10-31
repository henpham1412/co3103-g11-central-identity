package vn.edu.hcmut.co3103.identity.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "auth.login")
public class LoginPolicyProperties {

    @Positive
    private int maxFailedAttempts = 5;

    @NotNull
    private Duration lockoutDuration = Duration.ofMinutes(15);

    @AssertTrue(message = "Lockout duration must be positive")
    public boolean isLockoutDurationPositive() {
        return lockoutDuration == null || lockoutDuration.isPositive();
    }
}
