package vn.edu.hcmut.co3103.identity.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.common.MessageResponse;
import vn.edu.hcmut.co3103.identity.service.PasswordResetService;

@RestController
@RequestMapping({"/auth", "/api/v1/auth"})
@RequiredArgsConstructor
@Slf4j
public class PasswordResetController {
    private final PasswordResetService passwordResetService;

    @PostMapping(value = "/forgot-password", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        try {
            passwordResetService.forgotPassword(request);
        } catch (TaskRejectedException exception) {
            // Keep the acknowledgement generic when the bounded async queue is full.
            log.warn("Password recovery request could not be queued");
        }
        return ResponseEntity.ok(new MessageResponse(
                "If the email is eligible for recovery, password reset instructions have been sent."));
    }

    @PostMapping(value = "/reset-password", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok(new MessageResponse(
                "Password has been reset successfully. Please log in with your new password."));
    }
}
