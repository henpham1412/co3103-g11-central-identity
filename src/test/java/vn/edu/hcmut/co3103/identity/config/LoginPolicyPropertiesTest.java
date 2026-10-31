package vn.edu.hcmut.co3103.identity.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class LoginPolicyPropertiesTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void defaultsToFiveAttemptsAndFifteenMinutes() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            var policy = context.getBean(LoginPolicyProperties.class);
            assertThat(policy.getMaxFailedAttempts()).isEqualTo(5);
            assertThat(policy.getLockoutDuration()).isEqualTo(Duration.ofMinutes(15));
        });
    }

    @Test
    void bindsCustomThresholdAndDuration() {
        runner.withPropertyValues("auth.login.max-failed-attempts=2", "auth.login.lockout-duration=90s")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    var policy = context.getBean(LoginPolicyProperties.class);
                    assertThat(policy.getMaxFailedAttempts()).isEqualTo(2);
                    assertThat(policy.getLockoutDuration()).isEqualTo(Duration.ofSeconds(90));
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"auth.login.max-failed-attempts=0", "auth.login.max-failed-attempts=-1",
            "auth.login.lockout-duration=0s", "auth.login.lockout-duration=-1m",
            "auth.login.lockout-duration=invalid"})
    void rejectsInvalidPolicyAtStartup(String property) {
        runner.withPropertyValues(property).run(context -> assertThat(context).hasFailed());
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(LoginPolicyProperties.class)
    static class TestConfig {
    }
}
