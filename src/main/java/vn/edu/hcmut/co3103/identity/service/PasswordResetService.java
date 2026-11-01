package vn.edu.hcmut.co3103.identity.service;

import vn.edu.hcmut.co3103.identity.dto.auth.request.ForgotPasswordRequest;
import vn.edu.hcmut.co3103.identity.dto.auth.request.ResetPasswordRequest;
import vn.edu.hcmut.co3103.identity.repository.RecoveryQueue;
import java.net.InetAddress;

public interface PasswordResetService {
    void forgotPassword(ForgotPasswordRequest request, InetAddress clientIp);

    void issuePasswordReset(RecoveryQueue.Job job);

    void resetPassword(ResetPasswordRequest request);
}
