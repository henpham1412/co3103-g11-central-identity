package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class PasswordResetNotificationServiceTest {
    private static final String EMAIL = "recipient@example.com";
    private static final String TOKEN = "base64url_token-123";
    private static final String DEFAULT_BASE_URL = "http://localhost:3000/reset-password";

    @AfterEach
    void clearTransactionState() {
        TransactionSynchronizationManager.clear();
    }

    @Test
    void defaultConfigurationDeliversRecipientAndUsableLink(CapturedOutput output) {
        new ApplicationContextRunner().withUserConfiguration(PasswordResetNotificationService.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    context.getBean(PasswordResetNotificationService.class).send(EMAIL, TOKEN);
                    assertThat(output.getAll()).contains(
                            "Password reset delivery to " + EMAIL + ": " + DEFAULT_BASE_URL + "?token=" + TOKEN);
                });
    }

    @Test
    void configuredBaseUrlReachesDeliveryContract(CapturedOutput output) {
        String baseUrl = "https://identity.example/account/recover";
        new ApplicationContextRunner().withUserConfiguration(PasswordResetNotificationService.class)
                .withPropertyValues("app.reset-password.base-url=" + baseUrl)
                .run(context -> {
                    var notifications = spy(context.getBean(PasswordResetNotificationService.class));
                    notifications.send(EMAIL, TOKEN);
                    verify(notifications).deliver(EMAIL, baseUrl + "?token=" + TOKEN);
                    assertThat(output.getAll()).contains("Password reset delivery to " + EMAIL + ": " + baseUrl + "?token=" + TOKEN);
                });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void transactionalDeliveryRequiresSuccessfulCommit(boolean committed) {
        var notifications = spy(new PasswordResetNotificationService(DEFAULT_BASE_URL));
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        notifications.send(EMAIL, TOKEN);
        verify(notifications, never()).deliver(anyString(), anyString());
        var callbacks = TransactionSynchronizationManager.getSynchronizations();
        assertThat(callbacks).hasSize(1);
        if (committed) {
            callbacks.forEach(TransactionSynchronization::afterCommit);
        }
        callbacks.forEach(callback -> callback.afterCompletion(committed
                ? TransactionSynchronization.STATUS_COMMITTED : TransactionSynchronization.STATUS_ROLLED_BACK));
        verify(notifications, times(committed ? 1 : 0)).deliver(EMAIL, DEFAULT_BASE_URL + "?token=" + TOKEN);
    }
}
