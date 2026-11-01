package vn.edu.hcmut.co3103.identity.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.TransactionException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.common.MessageResponse;
import vn.edu.hcmut.co3103.identity.exception.RecoveryUnavailableException;
import vn.edu.hcmut.co3103.identity.service.PasswordResetService;
import vn.edu.hcmut.co3103.identity.web.ClientIpResolver;

@RestController
@RequestMapping({"/auth", "/api/v1/auth"})
@RequiredArgsConstructor
@Slf4j
public class PasswordResetController {
    private final PasswordResetService passwordResetService;
    private final ClientIpResolver clientIps;

    @PostMapping(value = "/forgot-password", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest servletRequest) {
        try {
            passwordResetService.forgotPassword(request, clientIps.resolve(servletRequest));
        } catch (DataAccessException | TransactionException exception) {
            log.warn("Password recovery admission unavailable ({})", exception.getClass().getSimpleName());
            throw new RecoveryUnavailableException(false);
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
