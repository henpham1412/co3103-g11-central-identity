package vn.edu.hcmut.co3103.identity.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.mail.autoconfigure.MailSenderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import vn.edu.hcmut.co3103.identity.support.InMemoryMailSender;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class MailConfigurationTest {
    private ApplicationContextRunner runner() throws IOException {
        var sources = new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yaml"));
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(MailSenderAutoConfiguration.class))
                .withUserConfiguration(InMemoryMailSender.class)
                .withInitializer(context -> sources.forEach(
                        source -> context.getEnvironment().getPropertySources().addLast(source)));
    }

    @Test
    void productionUsesSmtpAndBindsGmailSettingsWithoutConnecting() throws IOException {
        runner().withPropertyValues("MAIL_USERNAME=identity@example.com", "MAIL_PASSWORD=test-app-password")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(JavaMailSender.class)
                            .doesNotHaveBean(InMemoryMailSender.class);
                    var sender = context.getBean(JavaMailSenderImpl.class);
                    assertThat(sender.getHost()).isEqualTo("smtp.gmail.com");
                    assertThat(sender.getPort()).isEqualTo(587);
                    assertThat(sender.getUsername()).isEqualTo("identity@example.com");
                    assertThat(sender.getPassword()).isEqualTo("test-app-password");
                    assertThat(sender.getJavaMailProperties())
                            .containsEntry("mail.smtp.auth", "true")
                            .containsEntry("mail.smtp.starttls.enable", "true")
                            .containsEntry("mail.smtp.starttls.required", "true")
                            .containsEntry("mail.smtp.ssl.checkserveridentity", "true")
                            .containsEntry("mail.smtp.connectiontimeout", "5000")
                            .containsEntry("mail.smtp.timeout", "5000")
                            .containsEntry("mail.smtp.writetimeout", "5000")
                            .containsEntry("mail.debug", "false");
                });
    }

    @Test
    void testProfileReplacesSmtpWithInspectableMailbox() throws IOException {
        runner().withPropertyValues("spring.profiles.active=test").run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(JavaMailSender.class);
            assertThat(context.getBean(JavaMailSender.class)).isInstanceOf(InMemoryMailSender.class);
        });
    }
}
