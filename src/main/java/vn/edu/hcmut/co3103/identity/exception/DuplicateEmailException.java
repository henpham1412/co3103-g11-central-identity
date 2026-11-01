package vn.edu.hcmut.co3103.identity.exception;

public class DuplicateEmailException extends RuntimeException {

    public static final String MESSAGE = "Email already registered";

    public DuplicateEmailException() {
        super(MESSAGE);
    }
}
