package vn.edu.hcmut.co3103.identity.exception;

public class RecoveryUnavailableException extends RuntimeException {
    private final boolean rateLimited;

    public RecoveryUnavailableException(boolean rateLimited) {
        super("Password recovery is temporarily busy. Please try again later.");
        this.rateLimited = rateLimited;
    }

    public boolean isRateLimited() { return rateLimited; }
}
