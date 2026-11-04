package vn.edu.hcmut.co3103.identity.exception;

public class InvalidPasswordResetTokenException extends RuntimeException {
    public InvalidPasswordResetTokenException() {
        super("Invalid or expired password reset token");
    }
}
