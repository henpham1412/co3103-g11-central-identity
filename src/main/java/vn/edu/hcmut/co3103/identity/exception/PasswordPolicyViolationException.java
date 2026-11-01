package vn.edu.hcmut.co3103.identity.exception;

public class PasswordPolicyViolationException extends IllegalArgumentException {
    public PasswordPolicyViolationException() {
        super("Password does not meet the password policy");
    }
}
