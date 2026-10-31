package vn.edu.hcmut.co3103.identity.exception;

public class InvalidClientException extends RuntimeException {
    public InvalidClientException() {
        super("Client is invalid or inactive");
    }
}
