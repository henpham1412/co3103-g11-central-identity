package vn.edu.hcmut.co3103.identity.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/** One SMTP attempt. The durable queue owns retries and runs this outside any transaction. */
@Service
public class PasswordResetNotificationService {
    private final JavaMailSender mailSender;
    private final String from;
    private final String baseUrl;

    public PasswordResetNotificationService(JavaMailSender mailSender,
            @Value("${spring.mail.username:}") String from,
            @Value("${app.reset-password.base-url:http://localhost:3000/reset-password}") String baseUrl) {
        this.mailSender = mailSender;
        this.from = from;
        this.baseUrl = baseUrl;
    }

    public void send(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("Reset your Central Identity password");
        message.setText("Use the following link to reset your password. It expires in 15 minutes.\n\n"
                + baseUrl + "?token=" + token + "\n\nIf you did not request a password reset, ignore this email.");
        mailSender.send(message);
    }
}
