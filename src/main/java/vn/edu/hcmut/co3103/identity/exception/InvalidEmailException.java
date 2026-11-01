package vn.edu.hcmut.co3103.identity.exception;

/** Validation failure that must not be translated into a database/admission outage. */
public class InvalidEmailException extends RuntimeException {
    public InvalidEmailException() {
        super("Email must be valid Unicode");
    }
}
