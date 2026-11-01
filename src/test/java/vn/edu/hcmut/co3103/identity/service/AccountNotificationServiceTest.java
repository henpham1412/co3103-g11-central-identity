package vn.edu.hcmut.co3103.identity.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.concurrent.RejectedExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class AccountNotificationServiceTest {
    private final JavaMailSender sender = mock(JavaMailSender.class);
    private final TaskExecutor executor = mock(TaskExecutor.class);
    private final AccountNotificationService service = new AccountNotificationService(sender, executor, "identity@example.com");

    @BeforeEach void begin() { TransactionSynchronizationManager.initSynchronization(); }
    @AfterEach void end() { TransactionSynchronizationManager.clearSynchronization(); }

    @Test
    void bothNoticesAreSubmittedOnlyAfterCommitAndContainNoCredentials() {
        service.registrationConfirmed("new@example.com");
        service.passwordChanged("existing@example.com");
        verifyNoInteractions(sender, executor);
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);
        var tasks = ArgumentCaptor.forClass(Runnable.class);
        verify(executor, times(2)).execute(tasks.capture());
        verifyNoInteractions(sender);
        tasks.getAllValues().forEach(Runnable::run);
        var mails = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(sender, times(2)).send(mails.capture());
        assertThat(mails.getAllValues()).extracting(SimpleMailMessage::getSubject)
                .containsExactly("Welcome to Central Identity", "Your password has been changed");
        assertThat(mails.getAllValues().getFirst().getTo()).containsExactly("new@example.com");
        assertThat(mails.getAllValues().getLast().getTo()).containsExactly("existing@example.com");
        assertThat(mails.getAllValues()).allSatisfy(mail -> {
            assertThat(mail.getFrom()).isEqualTo("identity@example.com");
            assertThat(mail.getText()).doesNotContain("token=", "password:", "password=");
        });
    }

    @Test
    void rollbackDoesNotScheduleOrSendEmail() {
        service.registrationConfirmed("new@example.com");
        service.passwordChanged("existing@example.com");
        TransactionSynchronizationManager.getSynchronizations().forEach(sync ->
                sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
        verifyNoInteractions(sender, executor);
    }

    @Test
    void executorRejectionCannotFailTheCommittedOperationOrLeakExceptionDetails(CapturedOutput output) {
        doThrow(new RejectedExecutionException("private-exception-marker")).when(executor).execute(any());
        service.passwordChanged("private-recipient@example.com");
        assertThatCode(() -> TransactionSynchronizationManager.getSynchronizations()
                .forEach(TransactionSynchronization::afterCommit)).doesNotThrowAnyException();
        verifyNoInteractions(sender);
        assertThat(output.getAll()).contains("event=account_notification_failed", "reason=executor_unavailable")
                .doesNotContain("private-exception-marker", "private-recipient@example.com");
    }

    @Test
    void smtpFailureCannotEscapeOrLeakExceptionDetails(CapturedOutput output) {
        doAnswer(invocation -> { invocation.<Runnable>getArgument(0).run(); return null; })
                .when(executor).execute(any());
        doThrow(new MailSendException("private-smtp-credential")).when(sender).send(any(SimpleMailMessage.class));
        service.passwordChanged("private-recipient@example.com");
        assertThatCode(() -> TransactionSynchronizationManager.getSynchronizations()
                .forEach(TransactionSynchronization::afterCommit)).doesNotThrowAnyException();
        assertThat(output.getAll()).contains("event=account_notification_failed", "reason=delivery_failed")
                .doesNotContain("private-smtp-credential", "private-recipient@example.com");
    }
}
