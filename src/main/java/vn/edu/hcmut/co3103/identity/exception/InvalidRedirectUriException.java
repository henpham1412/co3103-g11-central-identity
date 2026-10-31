package vn.edu.hcmut.co3103.identity.exception;

public class InvalidRedirectUriException extends RuntimeException {
    public InvalidRedirectUriException() {
        super("Redirect URI is not registered for this client");
    }
}
