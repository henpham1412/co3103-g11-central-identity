package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import vn.edu.hcmut.co3103.identity.support.InMemoryMailSender;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;

class PasswordResetNotificationServiceTest {
    @Test
    void sendsConfiguredLinkAndSender() {
        var mailbox = new InMemoryMailSender();
        new ApplicationContextRunner().withUserConfiguration(PasswordResetNotificationService.class)
                .withBean(JavaMailSender.class, () -> mailbox)
                .withPropertyValues("spring.mail.username=identity@example.com",
                        "app.reset-password.base-url=https://frontend.example/reset-password")
                .run(context -> {
                    context.getBean(PasswordResetNotificationService.class).send("student@example.com", "raw-token");
                    assertThat(mailbox.getMessages()).singleElement().satisfies(message -> {
                        assertThat(message.getFrom()).isEqualTo("identity@example.com");
                        assertThat(message.getTo()).containsExactly("student@example.com");
                        assertThat(message.getText()).contains("https://frontend.example/reset-password?token=raw-token");
                    });
                });
    }

    @Test
    void transportFailurePropagatesToDurableWorkerWithoutImmediateRetryLoop() {
        var sender = mock(JavaMailSender.class);
        doThrow(new MailSendException("transport failure")).when(sender).send(any(SimpleMailMessage.class));
        var notifications = new PasswordResetNotificationService(sender, "identity@example.com", "https://example.com/reset");
        assertThatThrownBy(() -> notifications.send("student@example.com", "raw-token"))
                .isInstanceOf(MailSendException.class);
        verify(sender, times(1)).send(any(SimpleMailMessage.class));
    }
}
