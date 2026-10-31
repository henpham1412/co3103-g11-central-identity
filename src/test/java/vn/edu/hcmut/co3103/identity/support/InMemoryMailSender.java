package vn.edu.hcmut.co3103.identity.support;

import org.springframework.context.annotation.Profile;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Test-only mailbox: never packaged with production and never opens a network connection. */
@Component
@Profile("test")
public class InMemoryMailSender extends JavaMailSenderImpl {
    private final List<SimpleMailMessage> messages = new CopyOnWriteArrayList<>();

    @Override
    public void send(SimpleMailMessage... messages) {
        for (SimpleMailMessage message : messages) {
            this.messages.add(new SimpleMailMessage(message));
        }
    }

    public List<SimpleMailMessage> getMessages() {
        return messages.stream().map(SimpleMailMessage::new).toList();
    }

    public void clear() {
        messages.clear();
    }
}
