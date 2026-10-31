package vn.edu.hcmut.co3103.identity.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/** Email delivery stub; replace the body with the notification integration when available. */
@Service
@Slf4j
public class PasswordResetNotificationService {
    public void send(String email, String token) {
        // Neither the bearer token nor the recipient belongs in application logs.
        log.info("Simulated password reset email delivery (recipient and token redacted)");
    }
}
