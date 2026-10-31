package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import vn.edu.hcmut.co3103.identity.support.InMemoryMailSender;

import java.net.InetAddress;
import java.net.ServerSocket;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class PasswordResetNotificationServiceTest {
    private static final String EMAIL = "recipient@example.com";
    private static final String FROM = "identity@example.com";
    private static final String TOKEN = "base64url_token-123";
    private static final String DEFAULT_BASE_URL = "http://localhost:3000/reset-password";

    @AfterEach
    void clearTransactionState() {
        TransactionSynchronizationManager.clear();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "https://identity.example/account/recover"})
    void deliversRecipientSubjectAndUsableLinkWithoutLoggingCredentials(String configuredUrl, CapturedOutput output) {
        var mailbox = new InMemoryMailSender();
        var runner = new ApplicationContextRunner().withUserConfiguration(PasswordResetNotificationService.class)
                .withBean(JavaMailSender.class, () -> mailbox)
                .withPropertyValues("spring.mail.username=" + FROM);
        if (!configuredUrl.isEmpty()) runner = runner.withPropertyValues("app.reset-password.base-url=" + configuredUrl);
        String baseUrl = configuredUrl.isEmpty() ? DEFAULT_BASE_URL : configuredUrl;
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            context.getBean(PasswordResetNotificationService.class).send(EMAIL, TOKEN);
            assertThat(mailbox.getMessages()).singleElement().satisfies(message -> {
                assertThat(message.getFrom()).isEqualTo(FROM);
                assertThat(message.getTo()).containsExactly(EMAIL);
                assertThat(message.getSubject()).isEqualTo("Reset your Central Identity password");
                assertThat(message.getText()).contains(baseUrl + "?token=" + TOKEN, "15 minutes");
            });
            assertThat(output.getAll()).contains("Password reset email delivered to " + EMAIL)
                    .doesNotContain(TOKEN, baseUrl);
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void transactionalDeliveryRequiresSuccessfulCommit(boolean committed, CapturedOutput output) {
        var mailbox = new InMemoryMailSender();
        var notifications = new PasswordResetNotificationService(mailbox, FROM, DEFAULT_BASE_URL);
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        notifications.send(EMAIL, TOKEN);
        assertThat(mailbox.getMessages()).isEmpty();
        var callbacks = TransactionSynchronizationManager.getSynchronizations();
        assertThat(callbacks).hasSize(1);
        if (committed) callbacks.forEach(TransactionSynchronization::afterCommit);
        callbacks.forEach(callback -> callback.afterCompletion(committed
                ? TransactionSynchronization.STATUS_COMMITTED : TransactionSynchronization.STATUS_ROLLED_BACK));
        assertThat(mailbox.getMessages()).hasSize(committed ? 1 : 0);
        assertThat(output.getAll()).doesNotContain(TOKEN, DEFAULT_BASE_URL);
    }

    @Test
    void retriesTransientMailFailureUsingTheSameMessage(CapturedOutput output) {
        var sender = mock(JavaMailSender.class);
        var mailbox = new InMemoryMailSender();
        doThrow(new MailSendException("transport failure: " + TOKEN))
                .doAnswer(invocation -> { mailbox.send((SimpleMailMessage) invocation.getArgument(0)); return null; })
                .when(sender).send(any(SimpleMailMessage.class));
        new PasswordResetNotificationService(sender, FROM, DEFAULT_BASE_URL).send(EMAIL, TOKEN);
        verify(sender, times(2)).send(any(SimpleMailMessage.class));
        assertThat(mailbox.getMessages()).singleElement()
                .satisfies(message -> assertThat(message.getText()).contains(DEFAULT_BASE_URL + "?token=" + TOKEN));
        assertThat(output.getAll()).doesNotContain(TOKEN, DEFAULT_BASE_URL);
    }

    @Test
    void exhaustedDeliveryDoesNotThrowOrLogTransportExceptionContents(CapturedOutput output) {
        var sender = mock(JavaMailSender.class);
        String smtpPassword = "test-smtp-secret";
        doThrow(new MailSendException("credentials=" + smtpPassword + ", body=" + DEFAULT_BASE_URL + "?token=" + TOKEN))
                .when(sender).send(any(SimpleMailMessage.class));
        var notifications = new PasswordResetNotificationService(sender, FROM, DEFAULT_BASE_URL);
        assertThatCode(() -> notifications.send(EMAIL, TOKEN)).doesNotThrowAnyException();
        verify(sender, times(3)).send(any(SimpleMailMessage.class));
        assertThat(output.getAll()).contains("delivery failed for " + EMAIL, "after 3 attempts")
                .doesNotContain(TOKEN, DEFAULT_BASE_URL, smtpPassword);
    }

    @Test
    void realSmtpConnectionFailureIsContainedAndRedacted(CapturedOutput output) throws Exception {
        var sender = new JavaMailSenderImpl();
        sender.setHost("127.0.0.1");
        try (var unusedPort = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            sender.setPort(unusedPort.getLocalPort());
        }
        sender.getJavaMailProperties().setProperty("mail.smtp.connectiontimeout", "200");
        sender.getJavaMailProperties().setProperty("mail.smtp.timeout", "200");
        var notifications = new PasswordResetNotificationService(sender, FROM, DEFAULT_BASE_URL);
        assertThatCode(() -> notifications.send(EMAIL, TOKEN)).doesNotThrowAnyException();
        assertThat(output.getAll()).contains("delivery failed for " + EMAIL, "after 3 attempts")
                .doesNotContain(TOKEN, DEFAULT_BASE_URL);
    }
}
